// Copyright 2020 ETH Zurich
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

#ifndef HERCULES_FRAME_QUEUE_H
#define HERCULES_FRAME_QUEUE_H

#include "utils.h"

struct frame_queue {
	// reduce the memory footprint by using 16 bit ints instead of full 64 bits
	u16 *addrs;
	u64 prod;
	u64 cons;
	u16 size;
	u16 index_mask;
};

inline int frame_queue__init(struct frame_queue *fq, u16 size)
{
	if((size == 0) || ((size & (size - 1)) != 0)) {
		return EINVAL; // size is zero or not a power of two
	}
	fq->addrs = calloc(size, sizeof(__u16));
	if(fq->addrs == NULL) {
		return ENOMEM;
	}
	fq->size = size;
	fq->cons = fq->size;
	fq->index_mask = fq->size - 1;
	return EXIT_SUCCESS;
}

inline u16 frame_queue__prod_reserve(struct frame_queue *fq, u16 num)
{
	return umin16(atomic_load(&fq->cons) - fq->prod, num);
}

inline void frame_queue__prod_fill(struct frame_queue *fq, u16 offset, u64 addr)
{
	fq->addrs[(fq->prod + offset) & fq->index_mask] = addr >> XSK_UMEM__DEFAULT_FRAME_SHIFT;
}

inline void frame_queue__push(struct frame_queue *fq, u16 num)
{
	atomic_fetch_add(&fq->prod, num);
}

inline u16 frame_queue__cons_reserve(struct frame_queue *fq, u16 num)
{
	return umin16(atomic_load(&fq->prod) - fq->cons + fq->size, num);
}

inline u64 frame_queue__cons_fetch(struct frame_queue *fq, u16 offset)
{
	return fq->addrs[(fq->cons + offset) & fq->index_mask] << XSK_UMEM__DEFAULT_FRAME_SHIFT;
}

inline void frame_queue__pop(struct frame_queue *fq, u16 num)
{
	atomic_fetch_add(&fq->cons, num);
}

#endif
