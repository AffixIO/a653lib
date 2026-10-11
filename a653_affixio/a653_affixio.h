/* a653_affixio.h -- optional load-time check of partition images against an
 * AffixIO-format ML-DSA-65 signed manifest, using a PINNED public key.
 * No network, no JSON library. Off unless built with -DA653LIB_AFFIXIO=ON. */
#ifndef A653_AFFIXIO_H
#define A653_AFFIXIO_H
#include <stddef.h>
#include <stdint.h>

#define A653_AFFIXIO_PK_BYTES 1952

typedef struct {
  uint8_t pk[A653_AFFIXIO_PK_BYTES];   /* pinned ground signer key            */
  char key_id[64];                     /* expected key_id                     */
  int require_server;                  /* also require AffixIO countersign    */
  uint8_t server_pk[A653_AFFIXIO_PK_BYTES];
  char server_key_id[64];
  const char *state_path;              /* anti-rollback counters (may be NULL: no rollback check) */
} a653_affixio_trust_t;

/* 0 = verified. Non-zero = refuse; reason gets a short static code. */
int a653_affixio_verify_image(const a653_affixio_trust_t *t, const char *partition,
                              const char *image_path, const char *manifest_path,
                              const char **reason);

/* Load trust from env: A653_AFFIXIO_PUBKEY_FILE, A653_AFFIXIO_KEY_ID, A653_AFFIXIO_STATE,
 * optional A653_AFFIXIO_SERVER_PUBKEY_FILE + A653_AFFIXIO_SERVER_KEY_ID (then required). 0 = ok. */
int a653_affixio_trust_from_env(a653_affixio_trust_t *t, const char **reason);

/* Hook for start_partition_process: argv[0] (and a .wasm argv[1]) must each have <file>.a653sig. */
int a653_affixio_check_spawn(char *const argv[], int argc, const char **reason);

/* Exposed for tests. */
void a653_affixio_sha256(const uint8_t *d, size_t n, uint8_t out[32]);
size_t a653_affixio_b64dec(const char *in, uint8_t *out, size_t cap);
#endif
