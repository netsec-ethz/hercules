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

#ifndef __HERCULES_H__
#define __HERCULES_H__

#include <stdbool.h>
#include <linux/types.h>

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

#define HERCULES_MAX_HEADERLEN 256
// Path are specified as ETH/IP/UDP/SCION/UDP headers.
struct hercules_path {
	int headerlen;
	int payloadlen;
	int framelen;	//!< length of ethernet frame; headerlen + payloadlen
	const char header[HERCULES_MAX_HEADERLEN]; //!< headerlen bytes
	u16  checksum;	//SCION L4 checksum over header with 0 payload
};

// Connection information
struct hercules_app_addr {
	/** SCION IA. In network byte order. */
	u64 ia;
	/** SCION IP. In network byte order. */
	u32 ip;
	/** SCION/UDP port (L4, application). In network byte order. */
	u16 port;
};

void hercules_init(int ifindex, const struct hercules_app_addr local_addr, int queue);
void hercules_close();

struct hercules_stats {
  u64 start_time;
  u64 end_time;
  u64 now;

  u64 tx_npkts;
  u64 rx_npkts;

  u64 filesize;
  u32 framelen;
  u32 chunklen;
  u32 total_chunks;
  u32 completed_chunks; //!< either number of acked (for sender) or received (for receiver) chunks

  u32 rate_limit;
};

// Get the current stats of a running transfer.
// Returns stats with `start_time==0` if no transfer is active.
struct hercules_stats hercules_get_stats();

// Initiate transfer of file over the given path.
// Synchronous; returns when the transfer has been completed or if it has failed.
// Does not take ownership of `paths`.
// Retur
struct hercules_stats hercules_tx(const char *filename, const struct hercules_path *paths_per_dest, int num_dests, const int *num_paths, int max_paths, int max_rate_limit, bool enable_pcc, int xdp_mode);

// Initiate receiver, waiting for a transmitter to initiate the file transfer.
struct hercules_stats hercules_rx(const char *filename, int xdp_mode);

#endif // __HERCULES_H__
