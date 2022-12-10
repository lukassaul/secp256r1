/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256R1_ECDSA_H
#define SECP256R1_ECDSA_H

#include <stddef.h>

#include "scalar.h"
#include "group.h"
#include "ecmult.h"

static int secp256r1_ecdsa_sig_parse(secp256r1_scalar *r, secp256r1_scalar *s, const unsigned char *sig, size_t size);
static int secp256r1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const secp256r1_scalar *r, const secp256r1_scalar *s);
static int secp256r1_ecdsa_sig_verify(const secp256r1_scalar* r, const secp256r1_scalar* s, const secp256r1_ge *pubkey, const secp256r1_scalar *message);
static int secp256r1_ecdsa_sig_sign(const secp256r1_ecmult_gen_context *ctx, secp256r1_scalar* r, secp256r1_scalar* s, const secp256r1_scalar *seckey, const secp256r1_scalar *message, const secp256r1_scalar *nonce, int *recid);

#endif /* SECP256R1_ECDSA_H */
