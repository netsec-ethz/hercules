// Copyright 2019 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __HERCULES_BITSET_H__
#define __HERCULES_BITSET_H__

#include "hercules.h"
#include "utils.h"
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include "bpf/src/libbpf_util.h"

/** Simple bit-set that keeps track of number of elements in the set. */
struct bitset {
	unsigned int *bitmap;
	u32 num;
	u32 num_set;
	u32 max_set;
	pthread_spinlock_t lock;
};

#define HERCULES_BITSET_WORD_BITS (8 * sizeof(unsigned int))

void bitset__create(struct bitset *s, u32 num);

void bitset__destroy(struct bitset *s);

// Returns true iff the bit at index i in bitmap is set
bool bitset__check(struct bitset *s, u32 i);

// set bit at index i in bitmap.
// Returns the previous state of the bit.
bool bitset__set_mt_safe(struct bitset *s, u32 i);

// set bit at index i in bitmap.
// This function is not thread-safe.
bool bitset__set(struct bitset *s, u32 i);

// unset bit at index i in bitmap.
// Returns the previous state of the bit.
bool bitset__unset(struct bitset *s, u32 i);

// Reset the bitmap
// Unsets all entries in bitmap and reset the number of elements in the set
void bitset__reset(struct bitset *s);

// Find next entry in the set.
// Returns lowest index i greater or equal than pos such that bit i is set, or
// s->num if no such index exists.
u32 bitset__scan(struct bitset *s, u32 pos);

// Find next entry NOT in the set.
// Returns lowest index i greater or equal than pos such that bit i is NOT set,
// or s->num if no such index exists.
u32 bitset__scan_neg(struct bitset *s, u32 pos);

// Find nth entry NOT in the set.
// Returns nth lowest index i greater or equal than pos such that bit i is NOT set,
// or s->num if no such index exists.
u32 bitset__scan_neg_n(struct bitset *s, u32 pos, u32 n);

#endif // __HERCULES_BITSET_H__
