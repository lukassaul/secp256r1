/***********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256R1_SCALAR_REPR_H
#define SECP256R1_SCALAR_REPR_H

#include <stdint.h>

/** A scalar modulo the group order of the secp256r1 curve. */
typedef uint32_t secp256r1_scalar;

#define SECP256R1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0) (d0)

#endif /* SECP256R1_SCALAR_REPR_H */
