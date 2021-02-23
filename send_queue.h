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

#ifndef __HERCULES_SEND_QUEUE_H__
#define __HERCULES_SEND_QUEUE_H__

#include "hercules.h"
#include "utils.h"

#define CACHELINE_SIZE 64
#define SEND_QUEUE_ENTRY_SIZE 6
#define SEND_QUEUE_ENTRIES_PER_UNIT 7

// With this layout, 10 chunks fit into each cache line. Assumes a cache line size of 64 bytes.
//  sizeof(struct send_queue_unit) = 64
struct send_queue_unit {
	u32 chunk_idx[SEND_QUEUE_ENTRIES_PER_UNIT];
	u8 rcvr[SEND_QUEUE_ENTRIES_PER_UNIT];
	u8 paths[SEND_QUEUE_ENTRIES_PER_UNIT];
	char a[CACHELINE_SIZE - SEND_QUEUE_ENTRIES_PER_UNIT * SEND_QUEUE_ENTRY_SIZE]; // force padding to 64 bytes
};

// single producer, multi consumer queue
// the queue is empty if head == tail
struct send_queue {
	struct send_queue_unit *units;
	u32 size;
	u32 head;
	u32 tail;
	void *units_base;
};

void init_send_queue(struct send_queue *queue, u32 num_entries);
void destroy_send_queue(struct send_queue *queue);

// Checks if the send_queue has at least one free send_queue_unit slot.
// If yes, this function returns a pointer to that send_queue_unit.
// If no, this function returns NULL.
struct send_queue_unit *send_queue_reserve(struct send_queue *queue);

// Adds the send_queue_unit obtained by send_queue_reserve() to the queue.
// Do not call this function without previously calling send_queue_reserve(), the program will crash.
void send_queue_push(struct send_queue *queue);

// Pops a send_queue_unit off the queue and fills it into *unit.
// Returns false if the queue is empty, true if a send_queue_unit was popped successfully.
bool send_queue_pop(struct send_queue *queue, struct send_queue_unit *unit);

// Pops a send_queue_unit off the queue and fills it into *unit.
// If the queue is empty and block is true, this function blocks until some send_queue_unit is available.
// As soon as *block is false, send_queue_pop_wait stops blocking.
void send_queue_pop_wait(struct send_queue *queue, struct send_queue_unit *unit, bool *block);

#endif //__HERCULES_SEND_QUEUE_H__
