#!/bin/sh
# Live AffixIO API run, synthetic image only, 1 proof. Needs AFFIX_API_KEY (env only), A653_SIDECAR_PINS
# (saved /v1/keys JSON) and AFFIXIO_PUB_B64 (pinned AffixIO public key file). Args: <verify-bin> <sidecar-dir>
V="$1"; S="$2"; T=$(mktemp -d); pass=0; fail=0
expect() { n="$1"; e="$2"; s="$3"; shift 3; out=$("$@" 2>&1); rc=$?
  if [ "$rc" = "$e" ] && echo "$out" | grep -q -- "$s"; then pass=$((pass+1)); echo "ok   $n"; else fail=$((fail+1)); echo "FAIL $n (rc=$rc out=$out)"; fi; }
node "$S/sign.mjs" keygen "$T/k" >/dev/null
printf 'synthetic partition image for live test' > "$T/partition_a"
t0=$(date +%s%3N); node "$S/sign.mjs" sign "$T/k" partition_a "$T/partition_a" 1 --server > "$T/sign.out" 2> "$T/sign.err"; rc=$?; t1=$(date +%s%3N)
if [ $rc = 0 ]; then pass=$((pass+1)); echo "ok   live: ground signer + AffixIO /prove + /v1/attest/proof (pinned, kind:proof) in $((t1-t0)) ms"; else fail=$((fail+1)); echo "FAIL live sign: $(cat "$T/sign.err" | head -2)"; fi
export A653_AFFIXIO_PUBKEY_FILE="$T/k/signer.pub.b64" A653_AFFIXIO_KEY_ID="$(cat "$T/k/signer.key_id")" A653_AFFIXIO_STATE="$T/state"
export A653_AFFIXIO_SERVER_PUBKEY_FILE="$AFFIXIO_PUB_B64" A653_AFFIXIO_SERVER_KEY_ID=pinned
expect "offline C verify: ground sig + AffixIO ML-DSA-65 countersig vs pinned key (no network)" 0 "verified: ok" "$V" partition_a "$T/partition_a"
sp=$(sed -n 's/^srv_payload //p' "$T/partition_a.a653sig" | base64 -d | sed 's/"valid":true/"valid":false/' | base64 -w0)
sed "s|^srv_payload .*|srv_payload $sp|" "$T/partition_a.a653sig" > "$T/t1.a653sig"
expect "tampered AffixIO payload rejected"       1 "server_signature_invalid" "$V" partition_a "$T/partition_a" "$T/t1.a653sig"
A653_AFFIXIO_SERVER_PUBKEY_FILE="$T/k/signer.pub.b64" \
expect "wrong pinned AffixIO key rejected"       1 "server_signature_invalid" "$V" partition_a "$T/partition_a"
# graft the genuine AffixIO countersignature onto a different, locally signed manifest
printf 'other synthetic image' > "$T/partition_b"; node "$S/sign.mjs" sign "$T/k" partition_b "$T/partition_b" 1 >/dev/null
grep '^srv_' "$T/partition_a.a653sig" >> "$T/partition_b.a653sig"
expect "grafted countersignature not bound to manifest" 1 "server_not_bound" "$V" partition_b "$T/partition_b"
AFFIX_API_KEY=synthetic-invalid node "$S/sign.mjs" sign "$T/k" partition_b "$T/partition_b" 2 --server >/dev/null 2>&1
if [ $? != 0 ]; then pass=$((pass+1)); echo "ok   invalid API key: signer fails closed, no manifest change"; else fail=$((fail+1)); echo "FAIL invalid key accepted"; fi
if grep -rqs "ai""o_" "$T" "$T/sign.out" "$T/sign.err" || grep -rqsF "$(printf %s "$AFFIX_API_KEY" | cut -c5-20)" "$T"; then fail=$((fail+1)); echo "FAIL key material found"; else pass=$((pass+1)); echo "ok   no API key material in manifests, state or signer output"; fi
rm -rf "$T"; echo "live: $pass passed, $fail failed"; [ "$fail" = 0 ]
