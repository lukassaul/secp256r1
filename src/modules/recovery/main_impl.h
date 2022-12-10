/***********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256R1_MODULE_RECOVERY_MAIN_H
#define SECP256R1_MODULE_RECOVERY_MAIN_H

#include "../../../include/secp256r1_recovery.h"

static void secp256r1_ecdsa_recoverable_signature_load(const secp256r1_context* ctx, secp256r1_scalar* r, secp256r1_scalar* s, int* recid, const secp256r1_ecdsa_recoverable_signature* sig) {
    (void)ctx;
    if (sizeof(secp256r1_scalar) == 32) {
        /* When the secp256r1_scalar type is exactly 32 byte, use its
         * representation inside secp256r1_ecdsa_signature, as conversion is very fast.
         * Note that secp256r1_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        secp256r1_scalar_set_b32(r, &sig->data[0], NULL);
        secp256r1_scalar_set_b32(s, &sig->data[32], NULL);
    }
    *recid = sig->data[64];
}

static void secp256r1_ecdsa_recoverable_signature_save(secp256r1_ecdsa_recoverable_signature* sig, const secp256r1_scalar* r, const secp256r1_scalar* s, int recid) {
    if (sizeof(secp256r1_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        secp256r1_scalar_get_b32(&sig->data[0], r);
        secp256r1_scalar_get_b32(&sig->data[32], s);
    }
    sig->data[64] = recid;
}

int secp256r1_ecdsa_recoverable_signature_parse_compact(const secp256r1_context* ctx, secp256r1_ecdsa_recoverable_signature* sig, const unsigned char *input64, int recid) {
    secp256r1_scalar r, s;
    int ret = 1;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);
    ARG_CHECK(recid >= 0 && recid <= 3);

    secp256r1_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    secp256r1_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        secp256r1_ecdsa_recoverable_signature_save(sig, &r, &s, recid);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int secp256r1_ecdsa_recoverable_signature_serialize_compact(const secp256r1_context* ctx, unsigned char *output64, int *recid, const secp256r1_ecdsa_recoverable_signature* sig) {
    secp256r1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(recid != NULL);

    secp256r1_ecdsa_recoverable_signature_load(ctx, &r, &s, recid, sig);
    secp256r1_scalar_get_b32(&output64[0], &r);
    secp256r1_scalar_get_b32(&output64[32], &s);
    return 1;
}

int secp256r1_ecdsa_recoverable_signature_convert(const secp256r1_context* ctx, secp256r1_ecdsa_signature* sig, const secp256r1_ecdsa_recoverable_signature* sigin) {
    secp256r1_scalar r, s;
    int recid;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(sigin != NULL);

    secp256r1_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, sigin);
    secp256r1_ecdsa_signature_save(sig, &r, &s);
    return 1;
}

static int secp256r1_ecdsa_sig_recover(const secp256r1_scalar *sigr, const secp256r1_scalar* sigs, secp256r1_ge *pubkey, const secp256r1_scalar *message, int recid) {
    unsigned char brx[32];
    secp256r1_fe fx;
    secp256r1_ge x;
    secp256r1_gej xj;
    secp256r1_scalar rn, u1, u2;
    secp256r1_gej qj;
    int r;

    if (secp256r1_scalar_is_zero(sigr) || secp256r1_scalar_is_zero(sigs)) {
        return 0;
    }

    secp256r1_scalar_get_b32(brx, sigr);
    r = secp256r1_fe_set_b32(&fx, brx);
    (void)r;
    VERIFY_CHECK(r); /* brx comes from a scalar, so is less than the order; certainly less than p */
    if (recid & 2) {
        if (secp256r1_fe_cmp_var(&fx, &secp256r1_ecdsa_const_p_minus_order) >= 0) {
            return 0;
        }
        secp256r1_fe_add(&fx, &secp256r1_ecdsa_const_order_as_fe);
    }
    if (!secp256r1_ge_set_xo_var(&x, &fx, recid & 1)) {
        return 0;
    }
    secp256r1_gej_set_ge(&xj, &x);
    secp256r1_scalar_inverse_var(&rn, sigr);
    secp256r1_scalar_mul(&u1, &rn, message);
    secp256r1_scalar_negate(&u1, &u1);
    secp256r1_scalar_mul(&u2, &rn, sigs);
    secp256r1_ecmult(&qj, &xj, &u2, &u1);
    secp256r1_ge_set_gej_var(pubkey, &qj);
    return !secp256r1_gej_is_infinity(&qj);
}

int secp256r1_ecdsa_sign_recoverable(const secp256r1_context* ctx, secp256r1_ecdsa_recoverable_signature *signature, const unsigned char *msghash32, const unsigned char *seckey, secp256r1_nonce_function noncefp, const void* noncedata) {
    secp256r1_scalar r, s;
    int ret, recid;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256r1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);

    ret = secp256r1_ecdsa_sign_inner(ctx, &r, &s, &recid, msghash32, seckey, noncefp, noncedata);
    secp256r1_ecdsa_recoverable_signature_save(signature, &r, &s, recid);
    return ret;
}

int secp256r1_ecdsa_recover(const secp256r1_context* ctx, secp256r1_pubkey *pubkey, const secp256r1_ecdsa_recoverable_signature *signature, const unsigned char *msghash32) {
    secp256r1_ge q;
    secp256r1_scalar r, s;
    secp256r1_scalar m;
    int recid;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(pubkey != NULL);

    secp256r1_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, signature);
    VERIFY_CHECK(recid >= 0 && recid < 4);  /* should have been caught in parse_compact */
    secp256r1_scalar_set_b32(&m, msghash32, NULL);
    if (secp256r1_ecdsa_sig_recover(&r, &s, &q, &m, recid)) {
        secp256r1_pubkey_save(pubkey, &q);
        return 1;
    } else {
        memset(pubkey, 0, sizeof(*pubkey));
        return 0;
    }
}

#endif /* SECP256R1_MODULE_RECOVERY_MAIN_H */
