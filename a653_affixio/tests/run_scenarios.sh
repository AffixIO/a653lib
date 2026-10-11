#!/bin/sh
# Offline scenarios for the a653lib AffixIO verifier. No network. Args: <verify-bin> <spawn-hook-bin> <sidecar-dir>
V="$1"; H="$2"; S="$3"; T=$(mktemp -d); pass=0; fail=0
sign() { node "$S/sign.mjs" sign "$@" >/dev/null || exit 3; }
expect() { # name expected-exit expected-substring cmd...
  n="$1"; e="$2"; s="$3"; shift 3; out=$("$@" 2>&1); rc=$?
  if [ "$rc" = "$e" ] && echo "$out" | grep -q -- "$s"; then pass=$((pass+1)); echo "ok   $n"; else fail=$((fail+1)); echo "FAIL $n (rc=$rc out=$out)"; fi; }
node "$S/sign.mjs" keygen "$T/k" >/dev/null && node "$S/sign.mjs" keygen "$T/other" >/dev/null || exit 3
export A653_AFFIXIO_PUBKEY_FILE="$T/k/signer.pub.b64" A653_AFFIXIO_KEY_ID="$(cat "$T/k/signer.key_id")" A653_AFFIXIO_STATE="$T/state"
mkdir -p "$T/img"; printf 'partition A image v1' > "$T/img/partition_a"; printf 'partition B image' > "$T/img/partition_b"
sign "$T/k" partition_a "$T/img/partition_a" 1; sign "$T/k" partition_b "$T/img/partition_b" 1
expect "allow: valid signed image"               0 "verified: ok"            "$V" partition_a "$T/img/partition_a"
expect "allow: restart with same counter"        0 "verified: ok"            "$V" partition_a "$T/img/partition_a"
cp "$T/img/partition_a" "$T/a.bak"; printf 'X' >> "$T/img/partition_a"
expect "deny: tampered image"                    1 "image_hash_mismatch"     "$V" partition_a "$T/img/partition_a"
cp "$T/a.bak" "$T/img/partition_a"
# tamper the signed message (counter 1 -> 9) and keep the signature
msg=$(sed -n 2p "$T/img/partition_a.a653sig" | cut -c5- | base64 -d | sed 's/"counter":1/"counter":9/' | base64 -w0)
{ echo A653AFFIX1; echo "msg $msg"; sed -n 3p "$T/img/partition_a.a653sig"; } > "$T/tampered.a653sig"
expect "deny: tampered manifest (counter edit)"  1 "signature_invalid"       "$V" partition_a "$T/img/partition_a" "$T/tampered.a653sig"
expect "deny: manifest for another partition"    1 "partition_mismatch"      "$V" partition_b "$T/img/partition_b" "$T/img/partition_a.a653sig"
A653_AFFIXIO_PUBKEY_FILE="$T/other/signer.pub.b64" \
expect "deny: wrong pinned key"                  1 "signature_invalid"       "$V" partition_a "$T/img/partition_a"
A653_AFFIXIO_KEY_ID=deadbeefdeadbeef \
expect "deny: unexpected key_id"                 1 "untrusted_key_id"        "$V" partition_a "$T/img/partition_a"
# rollback / replay of an older manifest after an upgrade
cp "$T/img/partition_a.a653sig" "$T/v1.a653sig"; cp "$T/img/partition_a" "$T/v1.img"
printf 'partition A image v2' > "$T/img/partition_a"; sign "$T/k" partition_a "$T/img/partition_a" 2
expect "allow: upgrade to counter 2"             0 "verified: ok"            "$V" partition_a "$T/img/partition_a"
expect "deny: replay of older signed image"      1 "rollback"                "$V" partition_a "$T/v1.img" "$T/v1.a653sig"
expect "fail-closed: manifest missing"           1 "manifest_unreadable"     "$V" partition_a "$T/img/partition_a" "$T/nope.a653sig"
head -c 200 "$T/img/partition_a.a653sig" > "$T/trunc.a653sig"
expect "fail-closed: truncated manifest"         1 "manifest_unreadable"     "$V" partition_a "$T/img/partition_a" "$T/trunc.a653sig"
A653_AFFIXIO_PUBKEY_FILE= \
expect "fail-closed: no pinned key configured"   1 "pinned_key_missing"      "$V" partition_a "$T/img/partition_a"
A653_AFFIXIO_SERVER_PUBKEY_FILE="$T/other/signer.pub.b64" A653_AFFIXIO_SERVER_KEY_ID=x \
expect "fail-closed: server countersign required but absent" 1 "server_attestation_missing" "$V" partition_a "$T/img/partition_a"
expect "spawn hook: signed native partition"     0 "allowed ok"              "$H" "$T/img/partition_b"
printf 'wasm' > "$T/img/p_wamr"; sign "$T/k" p_wamr "$T/img/p_wamr" 1; printf 'guest' > "$T/img/g.wasm"
expect "spawn hook: unsigned .wasm guest refused" 1 "manifest_unreadable"    "$H" "$T/img/p_wamr" "$T/img/g.wasm"
sign "$T/k" g.wasm "$T/img/g.wasm" 1
expect "spawn hook: signed runtime + guest"      0 "allowed ok"              "$H" "$T/img/p_wamr" "$T/img/g.wasm"
perm=$(stat -c %a "$T/k/signer.json")
if [ "$perm" = 600 ] && ! grep -rqs "ai""o_" "$T/img" "$T/state"; then pass=$((pass+1)); echo "ok   no leakage: key 0600, no API key prefix in manifests/state"; else fail=$((fail+1)); echo "FAIL leakage ($perm)"; fi
if grep -q secret "$T/img/partition_a.a653sig"; then fail=$((fail+1)); echo "FAIL secret in manifest"; else pass=$((pass+1)); echo "ok   no signing secret in manifest"; fi
rm -rf "$T"; echo "scenarios: $pass passed, $fail failed"; [ "$fail" = 0 ]
