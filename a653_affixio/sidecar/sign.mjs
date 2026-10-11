// Ground/maintenance-side signer for a653lib partition images. Never runs on the target.
//   node sign.mjs keygen <keydir>
//   node sign.mjs sign <keydir> <partition> <image> <counter> [--server]
// --server: additionally obtains an AffixIO countersignature (POST /v1/circuits/simple_yesno/prove,
// then /v1/attest/proof), checked against PINNED keys (A653_SIDECAR_PINS = saved /v1/keys JSON).
// AFFIX_API_KEY is read from the environment only and never written or printed.
import fs from 'node:fs'; import path from 'node:path'; import crypto from 'node:crypto';
import { createLocalSigningKeyPair, signLocalPayload, verifyLocalAttestation, canonicalLocalPayload } from 'affixio';

const [cmd, keydir, ...rest] = process.argv.slice(2);
const API = (process.env.A653_SIDECAR_API_BASE || 'https://api.affix-io.com').replace(/\/$/, '');
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

if (cmd === 'keygen') {
  fs.mkdirSync(keydir, { recursive: true, mode: 0o700 });
  const k = createLocalSigningKeyPair();
  fs.writeFileSync(path.join(keydir, 'signer.json'), JSON.stringify(k), { mode: 0o600 });
  fs.writeFileSync(path.join(keydir, 'signer.pub.b64'), k.public_key_b64 + '\n');
  fs.writeFileSync(path.join(keydir, 'signer.key_id'), k.key_id + '\n');
  console.log(k.key_id);
} else if (cmd === 'sign') {
  const [partition, image, counterS] = rest; const server = rest.includes('--server');
  const counter = Number(counterS);
  if (!/^[A-Za-z0-9_.-]{1,63}$/.test(partition || '') || !Number.isSafeInteger(counter) || counter < 0) throw new Error('bad partition or counter');
  const k = JSON.parse(fs.readFileSync(path.join(keydir, 'signer.json'), 'utf8'));
  const payload = { schema: 'a653.partition-manifest.v1', partition, image_sha256: sha(fs.readFileSync(image)), counter };
  const lines = ['A653AFFIX1'];
  if (server) {
    const att = await countersign(sha(JSON.stringify(payload)));
    payload.affixio_proof_digest = att.signed_payload.proof_digest;
    const sp = JSON.stringify(att.signed_payload);
    if (sha(sp) !== att.attestation.payload_digest) throw new Error('server_payload_digest_mismatch');
    lines.push(null, null, 'srv_payload ' + Buffer.from(sp).toString('base64'), 'srv_sig ' + att.attestation.mldsa_signature_b64);
  }
  const a = signLocalPayload(payload, { hmacSecret: crypto.randomBytes(32).toString('hex'), secretKeyB64: k.secret_key_b64, publicKeyB64: k.public_key_b64 });
  const chk = verifyLocalAttestation(payload, a, { trustedKeys: [{ key_id: k.key_id, public_key_b64: k.public_key_b64 }] });
  if (!chk.valid) throw new Error('self_check_' + chk.reason);
  if (a.schema !== 'affix.local-signature.v2') throw new Error('expected_v2');
  // Same bytes the SDK signs for v2 (LOCAL_SIGNATURE_V2_PREFIX + canonical envelope).
  const msg = Buffer.from('affix.sdk.local-signature.v2\n' + canonicalLocalPayload({ domain: 'affix.sdk.local-signature.v2', key_id: a.key_id, payload, signed_at: a.signed_at }), 'utf8');
  const head = ['A653AFFIX1', 'msg ' + msg.toString('base64'), 'sig ' + a.mldsa_signature_b64];
  const out = server ? [...head, ...lines.slice(3)] : head;
  fs.writeFileSync(image + '.a653sig', out.join('\n') + '\n');
  console.log(JSON.stringify({ partition, counter, server, key_id: k.key_id }));
} else { console.error('usage: keygen <dir> | sign <dir> <partition> <image> <counter> [--server]'); process.exit(2); }

async function countersign(manifestDigest) {
  const key = process.env.AFFIX_API_KEY; const pinsFile = process.env.A653_SIDECAR_PINS;
  if (!key || !pinsFile) throw new Error('AFFIX_API_KEY and A653_SIDECAR_PINS required for --server');
  const pins = JSON.parse(fs.readFileSync(pinsFile, 'utf8'));
  const { AffixSDK, verifyAffixioAttestation } = await import('affixio');
  const base = fs.mkdtempSync(path.join(process.env.TMPDIR || '/tmp', 'a653-sidecar-'));
  const sdk = new AffixSDK({ apiKey: key, apiBase: API, operatorBaseDir: base, proofMode: 'ultrahonk', autoFlush: false });
  const now = Math.floor(Date.now() / 1000); const ref = manifestDigest;
  const witness = sdk.buildWitness('simple_yesno',
    { schema_id: 'a653_partition_manifest_v1', issuer_id: 'ground', issuer_pubkey_hash: '0x1', credential_id: ref, claim_value: 'load:approve', valid_from: now - 60, valid_until: now + 600 },
    { secret: ref, context_id: ref.slice(0, 32), required_claim_hash: 'load:approve' });
  const h = { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` };
  const t = () => AbortSignal.timeout(Number(process.env.A653_SIDECAR_TIMEOUT_MS || 8000));
  let r = await fetch(`${API}/v1/circuits/simple_yesno/prove`, { method: 'POST', headers: h, body: JSON.stringify({ witness, requestAttestation: false }), signal: t() });
  const p = await r.json(); if (!r.ok || !p.proof) throw new Error('prove_failed:' + (p.error || r.status));
  r = await fetch(`${API}/v1/attest/proof`, { method: 'POST', headers: h, body: JSON.stringify({ circuit_id: 'simple_yesno', proof: p.proof_id || p.proof }), signal: t() });
  const a = await r.json();
  if (!r.ok || a.valid !== true || a.decision !== 'yes' || a.circuit_binding !== 'server_prove_record' || a.proof_digest !== p.proof_digest) throw new Error('attest_failed:' + (a.error || r.status));
  const v = await verifyAffixioAttestation(a.signed_payload, a.attestation, { trustedKeys: pins, kind: 'proof', expectedCircuitId: 'simple_yesno' });
  if (!v.valid) throw new Error('attestation_' + v.reason);
  sdk.dispose?.(); fs.rmSync(base, { recursive: true, force: true });
  return a;
}
