/***********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256R1_SCALAR_REPR_H
#define SECP256R1_SCALAR_REPR_H

#include <stdint.h>

/** A scalar modulo the group order of the secp256r1 curve. */
typedef struct {
    uint32_t d[8];
} secp256r1_scalar;

#define SECP256R1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {{(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7)}}

#endif /* SECP256R1_SCALAR_REPR_H */
