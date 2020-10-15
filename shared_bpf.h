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

#pragma pack(push)
#pragma pack(1)

// XXX: from libscion/packet.h
struct scionhdr {
	/** Packet Type of the packet (version, dstType, srcType) */
	__u16 ver_dst_src;
	/** Total Length of the packet */
	__u16 total_len;
	/** Header length that includes the path */
	__u8 header_len;
	/** Offset of current Info opaque field*/
	__u8 current_iof;
	/** Offset of current Hop opaque field*/
	__u8 current_hof;
	/** next header type, shared with IP protocol number*/
	__u8 next_header;
};

struct scionaddrhdr_ipv4 {
	__u64 dst_ia;
	__u64 src_ia;
	__u32 dst_ip;
	__u32 src_ip;
};

#pragma pack(pop)

#define MAX_NUM_QUEUES 256
#define MAX_NUM_LOCAL_ADDRS 2
#define SCION_ENDHOST_PORT 30041

#endif //HERCULES_SCION_H
