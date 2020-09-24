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

#ifndef HERCULES_SCION_H
#define HERCULES_SCION_H

#include <linux/types.h>

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

#pragma pack(push)
#pragma pack(1)

// XXX: from libscion/packet.h
struct scionhdr {
	/** Packet Type of the packet (version, dstType, srcType) */
	u16 ver_dst_src;
	/** Total Length of the packet */
	u16 total_len;
	/** Header length that includes the path */
	u8 header_len;
	/** Offset of current Info opaque field*/
	u8 current_iof;
	/** Offset of current Hop opaque field*/
	u8 current_hof;
	/** next header type, shared with IP protocol number*/
	u8 next_header;
};

struct scionaddrhdr_ipv4 {
	u64 dst_ia;
	u64 src_ia;
	u32 dst_ip;
	u32 src_ip;
};

#pragma pack(pop)

#define MAX_NUM_QUEUES 256
#define MAX_NUM_LOCAL_ADDRS 2
#define SCION_ENDHOST_PORT 30041

#endif //HERCULES_SCION_H
