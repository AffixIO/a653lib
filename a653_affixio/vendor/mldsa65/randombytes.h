/* Verify-only build: key generation and signing are not available on target. */
#ifndef A653_AFFIXIO_RANDOMBYTES_H
#define A653_AFFIXIO_RANDOMBYTES_H
#include <stddef.h>
#include <stdint.h>
int randombytes(uint8_t *output, size_t n);
#endif
