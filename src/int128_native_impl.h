#ifndef SECP256R1_INT128_NATIVE_IMPL_H
#define SECP256R1_INT128_NATIVE_IMPL_H

#include "int128.h"

static SECP256R1_INLINE void secp256r1_u128_load(secp256r1_uint128 *r, uint64_t hi, uint64_t lo) {
    *r = (((uint128_t)hi) << 64) + lo;
}

static SECP256R1_INLINE void secp256r1_u128_mul(secp256r1_uint128 *r, uint64_t a, uint64_t b) {
   *r = (uint128_t)a * b;
}

static SECP256R1_INLINE void secp256r1_u128_accum_mul(secp256r1_uint128 *r, uint64_t a, uint64_t b) {
   *r += (uint128_t)a * b;
}

static SECP256R1_INLINE void secp256r1_u128_accum_u64(secp256r1_uint128 *r, uint64_t a) {
   *r += a;
}

static SECP256R1_INLINE void secp256r1_u128_rshift(secp256r1_uint128 *r, unsigned int n) {
   VERIFY_CHECK(n < 128);
   *r >>= n;
}

static SECP256R1_INLINE uint64_t secp256r1_u128_to_u64(const secp256r1_uint128 *a) {
   return (uint64_t)(*a);
}

static SECP256R1_INLINE uint64_t secp256r1_u128_hi_u64(const secp256r1_uint128 *a) {
   return (uint64_t)(*a >> 64);
}

static SECP256R1_INLINE void secp256r1_u128_from_u64(secp256r1_uint128 *r, uint64_t a) {
   *r = a;
}

static SECP256R1_INLINE int secp256r1_u128_check_bits(const secp256r1_uint128 *r, unsigned int n) {
   VERIFY_CHECK(n < 128);
   return (*r >> n == 0);
}

static SECP256R1_INLINE void secp256r1_i128_load(secp256r1_int128 *r, int64_t hi, uint64_t lo) {
    *r = (((uint128_t)(uint64_t)hi) << 64) + lo;
}

static SECP256R1_INLINE void secp256r1_i128_mul(secp256r1_int128 *r, int64_t a, int64_t b) {
   *r = (int128_t)a * b;
}

static SECP256R1_INLINE void secp256r1_i128_accum_mul(secp256r1_int128 *r, int64_t a, int64_t b) {
   int128_t ab = (int128_t)a * b;
   VERIFY_CHECK(0 <= ab ? *r <= INT128_MAX - ab : INT128_MIN - ab <= *r);
   *r += ab;
}

static SECP256R1_INLINE void secp256r1_i128_det(secp256r1_int128 *r, int64_t a, int64_t b, int64_t c, int64_t d) {
   int128_t ad = (int128_t)a * d;
   int128_t bc = (int128_t)b * c;
   VERIFY_CHECK(0 <= bc ? INT128_MIN + bc <= ad : ad <= INT128_MAX + bc);
   *r = ad - bc;
}

static SECP256R1_INLINE void secp256r1_i128_rshift(secp256r1_int128 *r, unsigned int n) {
   VERIFY_CHECK(n < 128);
   *r >>= n;
}

static SECP256R1_INLINE int64_t secp256r1_i128_to_i64(const secp256r1_int128 *a) {
   return *a;
}

static SECP256R1_INLINE void secp256r1_i128_from_i64(secp256r1_int128 *r, int64_t a) {
   *r = a;
}

static SECP256R1_INLINE int secp256r1_i128_eq_var(const secp256r1_int128 *a, const secp256r1_int128 *b) {
   return *a == *b;
}

static SECP256R1_INLINE int secp256r1_i128_check_pow2(const secp256r1_int128 *r, unsigned int n) {
   VERIFY_CHECK(n < 127);
   return (*r == (int128_t)1 << n);
}

#endif
