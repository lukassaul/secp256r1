/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256R1_ECKEY_H
#define SECP256R1_ECKEY_H

#include <stddef.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static int secp256r1_eckey_pubkey_parse(secp256r1_ge *elem, const unsigned char *pub, size_t size);
static int secp256r1_eckey_pubkey_serialize(secp256r1_ge *elem, unsigned char *pub, size_t *size, int compressed);

static int secp256r1_eckey_privkey_tweak_add(secp256r1_scalar *key, const secp256r1_scalar *tweak);
static int secp256r1_eckey_pubkey_tweak_add(secp256r1_ge *key, const secp256r1_scalar *tweak);
static int secp256r1_eckey_privkey_tweak_mul(secp256r1_scalar *key, const secp256r1_scalar *tweak);
static int secp256r1_eckey_pubkey_tweak_mul(secp256r1_ge *key, const secp256r1_scalar *tweak);

#endif /* SECP256R1_ECKEY_H */
