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

#include "shared_bpf.h"
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>

#ifndef NDEBUG
#define debug_printf(fmt, ...) printf("DEBUG: %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define debug_printf(...) ;
#endif

#ifndef likely
# define likely(x)              __builtin_expect(!!(x), 1)
#endif

#define CACHELINE_SIZE 64

#define HERCULES_MAX_HEADERLEN 256
struct hercules_path_header {
	const char header[HERCULES_MAX_HEADERLEN]; //!< headerlen bytes
	u16  checksum;	//SCION L4 checksum over header with 0 payload
};

// Path are specified as ETH/IP/UDP/SCION/UDP headers.
struct hercules_path {
	u64 next_handshake_at;
	int headerlen;
	int payloadlen;
	int framelen;	//!< length of ethernet frame; headerlen + payloadlen
	struct hercules_path_header *headers; //!< separate header for each destination IP address
	u8 num_headers; //!< number of different versions available for this path (i.e. different destination host IP addresses)
	atomic_bool enabled; // e.g. when a path has been revoked and no replacement is available, this will be set to false
	atomic_bool replaced;
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

struct local_addr { // local as in "relative to the local IA"
	u32 ip;
	u16 port;
};

typedef u64 ia;


void hercules_init(int ifindex, ia ia, const struct local_addr *local_addrs, int num_local_addrs, int queues[],
				   int num_queues, int mtu);
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

void allocate_path_headers(struct hercules_path *path, int num_headers);
void push_hercules_tx_paths(void);

// locks for working with the shared path memory
void acquire_path_lock(void);
void free_path_lock(void);

// Initiate transfer of file over the given path.
// Synchronous; returns when the transfer has been completed or if it has failed.
// Does not take ownership of `paths`.
// Retur
struct hercules_stats
hercules_tx(const char *filename, const struct hercules_app_addr *destinations, struct hercules_path *paths_per_dest,
			int num_dests, const int *num_paths, int max_paths, int max_rate_limit, bool enable_pcc, int xdp_mode);

// Initiate receiver, waiting for a transmitter to initiate the file transfer.
struct hercules_stats hercules_rx(const char *filename, int xdp_mode, bool configure_queues);

#endif // __HERCULES_H__
