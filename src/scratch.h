/***********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256R1_SCRATCH_H
#define SECP256R1_SCRATCH_H

/* The typedef is used internally; the struct name is used in the public API
 * (where it is exposed as a different typedef) */
typedef struct secp256r1_scratch_space_struct {
    /** guard against interpreting this object as other types */
    unsigned char magic[8];
    /** actual allocated data */
    void *data;
    /** amount that has been allocated (i.e. `data + offset` is the next
     *  available pointer)  */
    size_t alloc_size;
    /** maximum size available to allocate */
    size_t max_size;
} secp256r1_scratch;

static secp256r1_scratch* secp256r1_scratch_create(const secp256r1_callback* error_callback, size_t max_size);

static void secp256r1_scratch_destroy(const secp256r1_callback* error_callback, secp256r1_scratch* scratch);

/** Returns an opaque object used to "checkpoint" a scratch space. Used
 *  with `secp256r1_scratch_apply_checkpoint` to undo allocations. */
static size_t secp256r1_scratch_checkpoint(const secp256r1_callback* error_callback, const secp256r1_scratch* scratch);

/** Applies a check point received from `secp256r1_scratch_checkpoint`,
 *  undoing all allocations since that point. */
static void secp256r1_scratch_apply_checkpoint(const secp256r1_callback* error_callback, secp256r1_scratch* scratch, size_t checkpoint);

/** Returns the maximum allocation the scratch space will allow */
static size_t secp256r1_scratch_max_allocation(const secp256r1_callback* error_callback, const secp256r1_scratch* scratch, size_t n_objects);

/** Returns a pointer into the most recently allocated frame, or NULL if there is insufficient available space */
static void *secp256r1_scratch_alloc(const secp256r1_callback* error_callback, secp256r1_scratch* scratch, size_t n);

#endif
