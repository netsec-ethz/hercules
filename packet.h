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

#define SCION_ENDHOST_PORT 30041

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

// Structure of first RBUDP packet sent by sender.
// Integers all transmitted in little endian (host endianness).
struct rbudp_initial_pkt {
	__u64 filesize;
	__u32 chunklen;
	__u64 timestamp;
	__u8 path_index;
	__u8 flags;
};

#define HANDSHAKE_FLAG_SET_RETURN_PATH 0x1u

// Structure of ACK RBUDP packets sent by the receiver.
// Integers all transmitted in little endian (host endianness).
struct rbudp_ack_pkt {
	__u8 num_acks; //!< number of (valid) entries in `acks`
	struct {
		__u32 begin; //!< index of first chunk that is ACKed with this range
		__u32 end;   //!< one-past-the-last chunk that is ACKed with this range
	} acks[256]; //!< list of ranges that are ACKed
};

#define CONTROL_PACKET_TYPE_INITIAL 0
#define CONTROL_PACKET_TYPE_ACK 1
#define CONTROL_PACKET_TYPE_NACK 2

struct hercules_control_packet {
	__u8 type;
	union {
		struct rbudp_initial_pkt initial;
		struct rbudp_ack_pkt ack;
	} payload;
};

#pragma pack(pop)

#endif //HERCULES_SCION_H
