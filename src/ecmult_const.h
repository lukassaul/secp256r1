/***********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256R1_ECMULT_CONST_H
#define SECP256R1_ECMULT_CONST_H

#include "scalar.h"
#include "group.h"

/**
 * Multiply: R = q*A (in constant-time)
 * Here `bits` should be set to the maximum bitlength of the _absolute value_ of `q`, plus
 * one because we internally sometimes add 2 to the number during the WNAF conversion.
 * A must not be infinity.
 */
static void secp256r1_ecmult_const(secp256r1_gej *r, const secp256r1_ge *a, const secp256r1_scalar *q, int bits);

#endif /* SECP256R1_ECMULT_CONST_H */
