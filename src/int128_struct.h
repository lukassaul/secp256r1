#ifndef SECP256R1_INT128_STRUCT_H
#define SECP256R1_INT128_STRUCT_H

#include <stdint.h>
#include "util.h"

typedef struct {
  uint64_t lo;
  uint64_t hi;
} secp256r1_uint128;

typedef secp256r1_uint128 secp256r1_int128;

#endif
