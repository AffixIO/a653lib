# Optional AffixIO load-time verification for a653lib (`-DA653LIB_AFFIXIO=ON`, default OFF)

Before `start_partition_process()` spawns a partition, the binary (and a `.wasm` guest when the
runtime launcher is used) must carry `<file>.a653sig`: a manifest signed with ML-DSA-65 by a
**pinned** ground/maintenance key. Checked on target: signature, key_id, partition name,
SHA-256 of the image, and a monotonic counter (anti-rollback, `A653_AFFIXIO_STATE`). Optionally
also an AffixIO server countersignature (verified-proof attestation) against the pinned AffixIO key.
Any failure refuses the spawn (exit 1, like a failed `posix_spawn`). No network on target.

- `a653_affixio.c` – verifier (bundled SHA-256, strict base64, strict field checks; no JSON library).
- `vendor/mldsa65/` – PQClean ML-DSA-65 reference, verify-only (signing aborts).
- `sidecar/sign.mjs` – ground-side signer using the AffixIO SDK (affixio@2.0.3). Never on target.
- `tools/a653_affixio_verify` – CLI and `--bench N`.
- Tests: `cmake -S a653_affixio -B b && cmake --build b && (cd b && ctest)`; live: `tests/live_api.sh`.

| Env | Meaning |
|---|---|
| `A653_AFFIXIO_PUBKEY_FILE`, `A653_AFFIXIO_KEY_ID` | pinned ground signer key (base64) and id |
| `A653_AFFIXIO_STATE` | anti-rollback counter file |
| `A653_AFFIXIO_SERVER_PUBKEY_FILE`, `A653_AFFIXIO_SERVER_KEY_ID` | if set, AffixIO countersignature required |

Signer: `node sidecar/sign.mjs keygen <dir>`; `node sidecar/sign.mjs sign <dir> <partition> <image> <counter> [--server]`
(`--server` needs `AFFIX_API_KEY` in env and `A653_SIDECAR_PINS` = saved `/v1/keys`).
