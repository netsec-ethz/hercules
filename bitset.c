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

#include "bitset.h"
#include <stdlib.h>

void bitset__create(struct bitset *s, u32 num)
{
	s->bitmap = calloc((num + HERCULES_BITSET_WORD_BITS - 1) / HERCULES_BITSET_WORD_BITS,
	                   HERCULES_BITSET_WORD_BITS / 8);
	s->num = num;
	s->num_set = 0;
}

void bitset__destroy(struct bitset *s)
{
	free(s->bitmap);
	s->bitmap = NULL;
}
