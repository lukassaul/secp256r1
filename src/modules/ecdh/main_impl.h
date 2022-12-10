/***********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256R1_MODULE_ECDH_MAIN_H
#define SECP256R1_MODULE_ECDH_MAIN_H

#include "../../../include/secp256r1_ecdh.h"
#include "../../ecmult_const_impl.h"

static int ecdh_hash_function_sha256(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    unsigned char version = (y32[31] & 0x01) | 0x02;
    secp256r1_sha256 sha;
    (void)data;

    secp256r1_sha256_initialize(&sha);
    secp256r1_sha256_write(&sha, &version, 1);
    secp256r1_sha256_write(&sha, x32, 32);
    secp256r1_sha256_finalize(&sha, output);

    return 1;
}

const secp256r1_ecdh_hash_function secp256r1_ecdh_hash_function_sha256 = ecdh_hash_function_sha256;
const secp256r1_ecdh_hash_function secp256r1_ecdh_hash_function_default = ecdh_hash_function_sha256;

int secp256r1_ecdh(const secp256r1_context* ctx, unsigned char *output, const secp256r1_pubkey *point, const unsigned char *scalar, secp256r1_ecdh_hash_function hashfp, void *data) {
    int ret = 0;
    int overflow = 0;
    secp256r1_gej res;
    secp256r1_ge pt;
    secp256r1_scalar s;
    unsigned char x[32];
    unsigned char y[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);

    if (hashfp == NULL) {
        hashfp = secp256r1_ecdh_hash_function_default;
    }

    secp256r1_pubkey_load(ctx, &pt, point);
    secp256r1_scalar_set_b32(&s, scalar, &overflow);

    overflow |= secp256r1_scalar_is_zero(&s);
    secp256r1_scalar_cmov(&s, &secp256r1_scalar_one, overflow);

    secp256r1_ecmult_const(&res, &pt, &s, 256);
    secp256r1_ge_set_gej(&pt, &res);

    /* Compute a hash of the point */
    secp256r1_fe_normalize(&pt.x);
    secp256r1_fe_normalize(&pt.y);
    secp256r1_fe_get_b32(x, &pt.x);
    secp256r1_fe_get_b32(y, &pt.y);

    ret = hashfp(output, x, y, data);

    memset(x, 0, 32);
    memset(y, 0, 32);
    secp256r1_scalar_clear(&s);

    return !!ret & !overflow;
}

#endif /* SECP256R1_MODULE_ECDH_MAIN_H */
