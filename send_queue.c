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

#include "send_queue.h"
#include "hercules.h"
#include <stdlib.h>
#include <string.h>

void init_send_queue(struct send_queue *queue, u32 num_entries)
{
	queue->units = (struct send_queue_unit *) calloc(num_entries, sizeof(struct send_queue_unit));
	queue->size = num_entries;
	queue->head = 0;
	queue->tail = 0;
}

void destroy_send_queue(struct send_queue *queue)
{
	free(queue->units);
	queue->units = NULL;
}

// single producer queue: this does not need to be thread-safe
struct send_queue_unit *send_queue_reserve(struct send_queue *queue)
{
	u32 current_tail = atomic_load(&queue->tail);
	u32 new_tail = (current_tail + 1) % queue->size;
	if(new_tail == atomic_load(&queue->head)) {
		return NULL; // queue is full
	}

	return &queue->units[current_tail];
}

// single producer queue: this does not need to be thread-safe
void send_queue_push(struct send_queue *queue)
{
	u32 current_tail = atomic_load(&queue->tail);
	u32 new_tail = (current_tail + 1) % queue->size;
	if(new_tail == atomic_load(&queue->head)) {
		debug_printf("cannot push into full send_queue");
		exit(129);
	}
	atomic_store(&queue->tail, new_tail);
}

// returns false if queue empty
bool send_queue_pop(struct send_queue *queue, struct send_queue_unit *unit)
{
	while(true) {
		u32 current_head = atomic_load(&queue->head);
		if(current_head == atomic_load(&queue->tail)) {
			return false; // queue is empty
		}
		// TODO optimize: reserve before copying, release after
		memcpy(unit, &queue->units[current_head], sizeof(*unit));
		if(atomic_compare_exchange_strong(&queue->head, &current_head, (current_head + 1) % queue->size)) {
			return true;
		}
	}
}

// blocks if queue empty
void send_queue_pop_wait(struct send_queue *queue, struct send_queue_unit *unit)
{
	while(!send_queue_pop(queue, unit)) {
		// TODO back-off?
	}
}
