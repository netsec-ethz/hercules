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

#ifndef __HERCULES_UTILS_H__
#define __HERCULES_UTILS_H__

#include <time.h>
#include <errno.h>
#include <linux/types.h>
#include <stdio.h>

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

#ifndef NDEBUG
#define debug_printf(fmt, ...) printf("DEBUG: %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define debug_printf(...) ;
#endif

#ifndef likely
# define likely(x)              __builtin_expect(!!(x), 1)
#endif

u16 umin16(u16 a, u16 b);
u16 umax16(u16 a, u16 b);

u32 umin32(u32 a, u32 b);
u32 umax32(u32 a, u32 b);

u64 umin64(u64 a, u64 b);
u64 umax64(u64 a, u64 b);

u64 get_nsecs(void);

void sleep_until(u64 ns);
void sleep_nsecs(u64 ns);

#endif
