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

#include "utils.h"

u16 umin16(u16 a, u16 b)
{
	return (a < b) ? a : b;
}

u16 umax16(u16 a, u16 b)
{
	return (a > b) ? a : b;
}

u32 umin32(u32 a, u32 b)
{
	return (a < b) ? a : b;
}

u32 umax32(u32 a, u32 b)
{
	return (a > b) ? a : b;
}

u64 umin64(u64 a, u64 b)
{
	return (a < b) ? a : b;
}

u64 umax64(u64 a, u64 b)
{
	return (a > b) ? a : b;
}

u64 get_nsecs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

void sleep_until(u64 ns)
{
	struct timespec req;
	req.tv_sec = (time_t)(ns / 1000000000UL);
	req.tv_nsec = (long)(ns % 1000000000UL);
	clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &req, NULL);
}

void sleep_nsecs(u64 ns)
{
	// Use clock_nanosleep to avoid drift by repeated interrupts. See NOTES in man(2) nanosleep.
	sleep_until(get_nsecs() + ns);
}
