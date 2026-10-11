/* Verify-only build: any call means signing/keygen was reached, which must never happen on target. */
#include <stdlib.h>
#include "randombytes.h"
int randombytes(uint8_t *output, size_t n) { (void)output; (void)n; abort(); }
