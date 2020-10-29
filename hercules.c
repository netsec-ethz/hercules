// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2017 - 2018 Intel Corporation.
// Copyright(c) 2019 ETH Zurich.

// Enable extra warnings; cannot be enabled in CFLAGS because cgo generates a
// ton of warnings that can apparantly not be suppressed.
#pragma GCC diagnostic warning "-Wextra"

#include "hercules.h"
#include "packet.h"
#include <stdatomic.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/if_xdp.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <float.h>
#include <linux/bpf_util.h>

#include "bpf/src/libbpf.h"
#include "bpf/src/bpf.h"
#include "bpf/src/xsk.h"
#include "linux/filter.h" // actually linux/tools/include/linux/filter.h

#include "bitset.h"
#include "libscion_checksum.h"
#include "congestion_control.h"
#include "utils.h"
#include "send_queue.h"
#include "bpf_prgms.h"


#define L4_SCMP 1
// #define L4_UDP 17 //  == IPPROTO_UDP


#define NUM_FRAMES (4 * 1024)
#define BATCH_SIZE 64


#define RATE_LIMIT_CHECK 1000 // check rate limit every X packets
						// Maximum burst above target pps allowed
#define PATH_HANDSHAKE_TIMEOUT_NS 100000000 // send a path handshake every X=100 ms until the first response arrives

#define ACK_RATE_TIME_MS 100 // send ACKS after at most X milliseconds

static const int rbudp_headerlen = sizeof(u32) + sizeof(u8) + sizeof(seqnr);
static const u64 tx_handshake_timeout = 5e9;
#define PCC_NO_PATH UINT8_MAX // tell the receiver not to count the packet on any path


// exported from hercules.go
extern int HerculesGetReplyPath(const char *packetPtr, int length, struct hercules_path *reply_path);


struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	u32 outstanding_tx;
};

struct receiver_state_per_path {
	struct bitset seq_rcvd;
	seqnr nack_end;
	seqnr prev_nack_end;
};

struct receiver_state {
	atomic_uint_least64_t handshake_rtt;
	/** Filesize in bytes */
	size_t filesize;
	/** Size of file data (in byte) per packet */
	u32 chunklen;
	/** Number of packets that will make up the entire file. Equal to `ceil(filesize/chunklen)` */
	u32 total_chunks;
	/** Memory mapped file for receive */
	char *mem;
	int control_sock_fd;

	struct bitset received_chunks;

	// XXX: reads/writes to this is are a huge data race. Need to sync.
	char rx_sample_buf[XSK_UMEM__DEFAULT_FRAME_SIZE];
	int rx_sample_len;

	// Start/end time of the current transfer
	u64 start_time;
	u64 end_time;
	u64 cts_sent_at;

	u8 num_tracked_paths;
	struct receiver_state_per_path path_state[256];
};

struct sender_state_per_receiver {
	u64 prev_round_start;
	u64 prev_round_end;
	u64 prev_slope;
	u64 ack_wait_duration;
	u32 prev_chunk_idx;
	bool finished;
	/** Next batch should be sent via this path */
	u8 path_index;

	struct bitset acked_chunks;
	atomic_uint_least64_t handshake_rtt; // Handshake RTT in ns

	u32 num_paths;
	u32 return_path_idx;
	struct hercules_app_addr addr;
	struct hercules_path *paths;
	struct ccontrol_state *cc_states;
	bool cts_received;
};

struct sender_state {
	/** Filesize in bytes */
	size_t filesize;
	/** Size of file data (in byte) per packet */
	u32 chunklen;
	/** Number of packets that will make up the entire file. Equal to `ceil(filesize/chunklen)` */
	u32 total_chunks;
	/** Memory mapped file for receive */
	char *mem;
	int control_socket_fd;

	_Atomic u32 rate_limit;

	// Start/end time of the current transfer
	u64 start_time;
	u64 end_time;

	u32 num_receivers;
	struct sender_state_per_receiver *receiver;
	u32 max_paths_per_rcvr;

	// shared with Go
	struct hercules_path *shd_paths;
	const int *shd_num_paths;

	atomic_bool has_new_paths;
};

typedef int xskmap;

// XXX: cleanup naming: these things are called `opt_XXX` because they corresponded to options in the example application.
static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static char *opt_ifname = "";
static int opt_ifindex;
static int num_queues;
static int *queues;
static ia local_ia; // local as in "our IA"
static int num_local_addrs; // local as in "relative to our IA"
static struct local_addr *local_addrs;
static int *ethtool_rules = NULL; // rule IDs configured on receiver side
static int num_ethtool_rules = 0;

static u32 prog_id;

static struct receiver_state *rx_state;
static struct sender_state *tx_state;
static struct send_queue send_queue;

// State for transmit rate control
static size_t tx_npkts;
static size_t tx_npkts_queued;
static u64 prev_rate_check;
static size_t prev_tx_npkts_queued;
// State for receive rate, for stat dump only
static size_t rx_npkts;

static bool running;
static int ether_size;


/**
 * @param scionaddrhdr
 * @return The receiver index given by the sender address in scionaddrhdr
 */
static u32 rcvr_by_src_address(const struct scionaddrhdr_ipv4 *scionaddrhdr, const struct udphdr *udphdr)
{
	u32 r;
	for(r = 0; r < tx_state->num_receivers; r++) {
		struct hercules_app_addr *addr = &tx_state->receiver[r].addr;
		if(scionaddrhdr->src_ia == addr->ia && scionaddrhdr->src_ip == addr->ip && udphdr->uh_sport == addr->port) {
			break;
		}
	}
	return r;
}

static void fill_rbudp_pkt(void *rbudp_pkt, u32 chunk_idx, u8 path_idx, seqnr sequence_number, const char *data,
						   size_t n, size_t payloadlen);

static bool rbudp_parse_initial(const char *pkt, size_t len, struct rbudp_initial_pkt *parsed_pkt);

static void stitch_checksum(const struct hercules_path *path, u16 precomputed_checksum, char *pkt);

static bool rx_received_all(const struct receiver_state *r)
{
	return (r->received_chunks.num_set == r->total_chunks);
}

static bool tx_acked_all(const struct sender_state *t)
{
	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		if(t->receiver[r].acked_chunks.num_set != t->total_chunks) {
			return false;
		}
	}
	return true;
}

static void set_rx_sample(struct receiver_state *r, const char *pkt, int len)
{
	r->rx_sample_len = len;
	memcpy(r->rx_sample_buf, pkt, len);
}

static void remove_xdp_program(void)
{
	u32 curr_prog_id = 0;

	if(bpf_get_link_xdp_id(opt_ifindex, &curr_prog_id, opt_xdp_flags)) {
		printf("bpf_get_link_xdp_id failed\n");
		exit(EXIT_FAILURE);
	}
	if(prog_id == curr_prog_id)
		bpf_set_link_xdp_fd(opt_ifindex, -1, opt_xdp_flags);
	else if(!curr_prog_id)
		printf("couldn't find a prog id on a given interface\n");
	else
		printf("program on interface changed, not removing\n");
}

static void unconfigure_queues();

static void __exit_with_error(int error, const char *file, const char *func, int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func, line, error, strerror(error));
	remove_xdp_program();
	unconfigure_queues();
	exit(EXIT_FAILURE);
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, __LINE__)

static void close_xsk(struct xsk_socket_info *xsk)
{
	struct xsk_umem *umem = xsk->umem->umem;  // umem per socket
	// Removes socket and frees xsk
	xsk_socket__delete(xsk->xsk);
	free(xsk);
	xsk_umem__delete(umem);
	remove_xdp_program();
}

// XXX: from lib/scion/udp.c
/*
 * Calculate UDP checksum
 * Same as regular IP/UDP checksum but IP addrs replaced with SCION addrs
 * buf: Pointer to start of SCION packet
 * len: SCION packet length
 * return value: Checksum value or 0 iff input is invalid
 */
u16 scion_udp_checksum(const u8 *buf, int len)
{
	chk_input chk_input_s;
	chk_input *input = init_chk_input(&chk_input_s, 5); // initialize checksum_parse for 5 chunks
	if(!input) {
		debug_printf("Unable to initalize checksum input: %p", input);
		return 0;
	}
	const u8 *udp_hdr;
	u16 l4_type;
	u16 payload_len, blank_sum = 0;

	// Address header (without padding) // go go/lib/hpkt/write.go padds at l.42
	chk_add_chunk(input, buf + 8, 24);

	const u8 *ptr = buf;
	// Include l4_type protocol number, in network order
	l4_type = htons((u16) IPPROTO_UDP);
	const struct scionhdr *scionh = (const struct scionhdr *) ptr;
	udp_hdr = ptr + scionh->header_len * 8;
	// L4 protocol type
	chk_add_chunk(input, (u8 *) &l4_type, 2);
	// udp src+dst port and len fields.
	ptr = chk_add_chunk(input, udp_hdr, 6);
	// Use blank checksum field
	chk_add_chunk(input, (u8 *) (&blank_sum), 2);
	ptr += 2; // Skip over packet checksum
	// Length in UDP header includes header size, so subtract it.
	payload_len = ntohs(*(u16 *) (udp_hdr + 4)) - 8;
	if(payload_len != len - 8) {
		debug_printf("Invalid payload_len: Got %u, Expected: %d", payload_len, len - 8);
		return 0;
	}
	chk_add_chunk(input, ptr, payload_len);

	u16 computed_checksum = checksum(input);
	return computed_checksum;
}

// Parse ethernet/IP/UDP/SCION/UDP packet,
// this is an extension to the parse_pkt
// function below only doing the checking
// that the BPF program has not already done.
//
// The BPF program writes the offset and the
// addr_idx to the first two words, set
// these arguments to -1 to use them.
static const char *parse_pkt_fast_path(const char *pkt, size_t length, bool check, size_t offset)
{
	if(offset == UINT32_MAX) {
		offset = *(int *) pkt;
	}
	if(check) {
		// we compute these pointers here again so that we do not have to pass it from kernel space into user space
		// which could negatively affect the performance in the case when the checksum is not verified
		struct scionhdr *scionh = (struct scionhdr *)
				(pkt + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
		struct udphdr *l4udph = (struct udphdr *) (pkt + offset) - 1;

		u16 header_checksum = l4udph->check;
		u16 computed_checksum = scion_udp_checksum((u8 *) scionh, length - offset + sizeof(struct udphdr));
		if(header_checksum != computed_checksum) {
			debug_printf("Checksum in SCION/UDP header %u "
						 "does not match computed checksum %u",
						 ntohs(header_checksum), ntohs(computed_checksum));
			return NULL;
		}
	}
	return pkt + offset;
}

// Parse ethernet/IP/UDP/SCION/UDP packet,
// check that it is addressed to us,
// check SCION-UDP checksum if set.
// sets scionaddrh_o to SCION address header, if provided
// return rbudp-packet (i.e. SCION/UDP packet payload)
static const char *parse_pkt(const char *pkt, size_t length, bool check, const struct scionaddrhdr_ipv4 **scionaddrh_o,
							 const struct udphdr **udphdr_o)
{
	// Parse Ethernet frame
	if(sizeof(struct ether_header) > length) {
		debug_printf("too short for eth header: %zu", length);
		return NULL;
	}
	const struct ether_header *eh = (const struct ether_header *) pkt;
	if(eh->ether_type != htons(ETHERTYPE_IP)) { // TODO: support VLAN etc?
		debug_printf("not IP");
		return NULL;
	}
	size_t offset = sizeof(struct ether_header);

	// Parse IP header
	if(offset + sizeof(struct iphdr) > length) {
		debug_printf("too short for iphdr: %zu %zu", offset, length);
		return NULL;
	}
	const struct iphdr *iph = (const struct iphdr *) (pkt + offset);
	if(iph->protocol != IPPROTO_UDP) {
		debug_printf("not UDP: %u, %zu", iph->protocol, offset);
		return NULL;
	}
	int addr_idx = -1;
	for(int i = 0; i < num_local_addrs; i++) {
		if(iph->daddr == local_addrs[i].ip) {
			addr_idx = i;
			break;
		}
	}
	if(addr_idx == -1) {
		debug_printf("not addressed to us (IP overlay)");
		return NULL;
	}
	offset += iph->ihl * 4u; // IHL is header length, in number of 32-bit words.

	// Parse UDP header
	if(offset + sizeof(struct udphdr) > length) {
		debug_printf("too short for udphdr: %zu %zu", offset, length);
		return NULL;
	}
	const struct udphdr *udph = (const struct udphdr *) (pkt + offset);
	if(udph->dest != htons(SCION_ENDHOST_PORT)) {
		debug_printf("not to SCION endhost port: %u", ntohs(udph->dest));
		return NULL;
	}
	offset += sizeof(struct udphdr);

	// Parse SCION Common header
	if(offset + sizeof(struct scionhdr) > length) {
		debug_printf("too short for SCION header: %zu %zu", offset, length);
		return NULL;
	}

	const struct scionhdr *scionh = (const struct scionhdr *) (pkt + offset);
	const u16 expected_ver_dst_src = htons(0 << 12 | 1 << 6 | 1 << 0); // version: 0, dst, src: 1 (IPv4)
	if(scionh->ver_dst_src != expected_ver_dst_src) {
		debug_printf("SCION version != 0 or src/dst address type != IPv4. ver: %u, dst: %u, src: %u",
					 ntohs(scionh->ver_dst_src) >> 12 & 0x03,
					 ntohs(scionh->ver_dst_src) >> 6 & 0x3f,
					 ntohs(scionh->ver_dst_src) >> 0 & 0x3f);
		return NULL;
	}
	if(scionh->next_header != IPPROTO_UDP) {
		if(scionh->next_header == L4_SCMP) {
			debug_printf("SCION/SCMP L4: not implemented, ignoring...");
		} else {
			debug_printf("unknown SCION L4: %u", scionh->next_header);
		}
		return NULL;
	}
	const struct scionaddrhdr_ipv4 *scionaddrh = (const struct scionaddrhdr_ipv4 *) (pkt + offset + sizeof(struct scionhdr));
	if(scionaddrh->dst_ia != local_ia) {
		debug_printf("not addressed to us (IA)");
		return NULL;
	}
	if(scionaddrh->dst_ip != local_addrs[addr_idx].ip) {
		debug_printf("not addressed to us (IP in SCION hdr)");
		return NULL;
	}

	offset += scionh->header_len * 8; // Header length is in lineLen of 8 bytes

	// Finally parse the L4-UDP header
	if(offset + sizeof(struct udphdr) > length) {
		debug_printf("too short for SCION/UDP header: %zu %zu", offset, length);
		return NULL;
	}

	const struct udphdr *l4udph = (const struct udphdr *) (pkt + offset);
	if(l4udph->dest != local_addrs[addr_idx].port) {
		debug_printf("not addressed to us (L4 UDP port): %u", ntohs(l4udph->dest));
		return NULL;
	}

	offset += sizeof(struct udphdr);
	if(scionaddrh_o != NULL) {
		*scionaddrh_o = scionaddrh;
	}
	if(udphdr_o != NULL) {
		*udphdr_o = l4udph;
	}
	return parse_pkt_fast_path(pkt, length, check, offset);
}

static bool recv_rbudp_control_pkt(int sockfd, char *buf, size_t buflen, const char **payload, int *payloadlen,
								   const struct scionaddrhdr_ipv4 **scionaddrh, const struct udphdr **udphdr)
{
	ssize_t len = recv(sockfd, buf, buflen, 0); // XXX set timeout
	if(len == -1) {
		if(errno == EAGAIN || errno == EINTR) {
			return false;
		}
		exit_with_error(errno); // XXX: are there situations where we want to try again?
	}

	const char *rbudp_pkt = parse_pkt(buf, len, true, scionaddrh, udphdr);
	if(rbudp_pkt == NULL) {
		return false;
	}

	const size_t rbudp_len = len - (rbudp_pkt - buf);
	if(rbudp_len < sizeof(u32)) {
		return false;
	}
	u32 chunk_idx;
	memcpy(&chunk_idx, rbudp_pkt, sizeof(u32));
	if(chunk_idx != UINT_MAX) {
		return false;
	}

	atomic_fetch_add(&rx_npkts, 1);

	*payload = rbudp_pkt + rbudp_headerlen;
	*payloadlen = rbudp_len - rbudp_headerlen;
	return true;
}

static bool handle_rbudp_data_pkt(const char *pkt, size_t length)
{
	if(length < rbudp_headerlen + rx_state->chunklen) {
		return false;
	}

	u32 chunk_idx;
	memcpy(&chunk_idx, pkt, sizeof(u32));
	if(chunk_idx >= rx_state->total_chunks) {
		if(chunk_idx == UINT_MAX) {
			// control packet is handled elsewhere
		} else {
			fprintf(stderr, "ERROR: chunk_idx larger than expected: %u >= %u\n",
					chunk_idx, rx_state->total_chunks);
		}
		return false;
	}

	u8 path_idx;
	mempcpy(&path_idx, &pkt[4], sizeof(u8));
	if (path_idx < PCC_NO_PATH) {
		seqnr sequence_number;
		memcpy(&sequence_number, &pkt[5], sizeof(seqnr));
		if(rx_state->path_state[path_idx].seq_rcvd.bitmap == NULL) {
			bitset__create(&rx_state->path_state[path_idx].seq_rcvd, 2 * rx_state->total_chunks);
			// TODO work out wrap-around
		}
		bitset__set_mt_safe(&rx_state->path_state[path_idx].seq_rcvd, sequence_number);

		u8 old_num = atomic_load(&rx_state->num_tracked_paths);
		while(old_num < path_idx + 1) { // update num_tracked_paths
			atomic_compare_exchange_strong(&rx_state->num_tracked_paths, &old_num, path_idx + 1);
		}
	}
	// mark as received in received_chunks bitmap
	bool prev = bitset__set_mt_safe(&rx_state->received_chunks, chunk_idx);
	if(!prev) {
		const char *payload = pkt + rbudp_headerlen;
		const size_t chunk_start = (size_t) chunk_idx * rx_state->chunklen;
		const size_t len = umin64(rx_state->chunklen, rx_state->filesize - chunk_start);
		memcpy(rx_state->mem + chunk_start, payload, len);
	}
	return true;
}


static struct xsk_umem_info *xsk_configure_umem(void *buffer, u64 size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if(!umem)
		exit_with_error(errno);

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
						   NULL);
	if(ret)
		exit_with_error(-ret);

	umem->buffer = buffer;
	return umem;
}

static void submit_initial_rx_frames(struct xsk_umem_info *umem)
{
	int initial_kernel_rx_frame_count = XSK_RING_PROD__DEFAULT_NUM_DESCS - BATCH_SIZE;
	u32 idx;
	int ret = xsk_ring_prod__reserve(&umem->fq,
									 initial_kernel_rx_frame_count,
									 &idx);
	if(ret != initial_kernel_rx_frame_count)
		exit_with_error(-ret);
	for(int i = 0; i < initial_kernel_rx_frame_count; i++)
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * XSK_UMEM__DEFAULT_FRAME_SIZE;
	xsk_ring_prod__submit(&umem->fq, initial_kernel_rx_frame_count);
}

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem, int libbpf_flags, int queue, int bind_flags)
{
	struct xsk_socket_config cfg;
	struct xsk_socket_info *xsk;
	int ret;

	xsk = calloc(1, sizeof(*xsk));
	if(!xsk)
		exit_with_error(errno);

	xsk->umem = umem;
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg.libbpf_flags = libbpf_flags;
	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = bind_flags;
	ret = xsk_socket__create(&xsk->xsk, opt_ifname, queue, umem->umem, &xsk->rx, &xsk->tx, &cfg);
	if(ret)
		exit_with_error(-ret);

	ret = bpf_get_link_xdp_id(opt_ifindex, &prog_id, opt_xdp_flags);
	if(ret)
		exit_with_error(-ret);

	return xsk;
}

static struct xsk_umem_info *create_umem()
{
	void *bufs;
	int ret = posix_memalign(&bufs, getpagesize(), /* PAGE_SIZE aligned */
							 NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
	if(ret)
		exit_with_error(ret);

	struct xsk_umem_info *umem;
	umem = xsk_configure_umem(bufs, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
	return umem;
}

static struct xsk_socket_info *create_xsk_with_umem(int libbpf_flags, int queue, int bind_flags)
{
	struct xsk_umem_info *umem = create_umem();
	return xsk_configure_socket(umem, libbpf_flags, queue, bind_flags);
}

static void kick_tx(struct xsk_socket_info *xsk)
{
	int ret;
	do {
		ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	} while(ret < 0 && errno == EAGAIN);

	if(ret < 0 && errno != ENOBUFS && errno != EBUSY) {
		exit_with_error(errno);
	}
}

// Pop entries from completion ring.
// XXX: Here we SHOULD be updating the bookeeping for which frames are safe to be used for sending.
//      But we currently don't so the only thing this does is freeng up the completion ring.
static void pop_completion_ring(struct xsk_socket_info *xsk)
{
	if(!xsk->outstanding_tx)
		return;

	u32 idx;
	size_t entries = xsk_ring_cons__peek(&xsk->umem->cq, SIZE_MAX, &idx);
	if(likely(entries > 0)) {
		xsk_ring_cons__release(&xsk->umem->cq, entries);
		xsk->outstanding_tx -= entries;
		atomic_fetch_add(&tx_npkts, entries);
	}
}

static u32 ack__max_num_entries(u32 len)
{
	struct rbudp_ack_pkt ack; // dummy declval
	return umin32(UINT8_MAX - 1, (len - sizeof(ack.num_acks)) / sizeof(ack.acks[0]));
}

static u32 ack__len(const struct rbudp_ack_pkt *ack)
{
	return sizeof(ack->num_acks) + ack->num_acks * sizeof(ack->acks[0]);
}

static u32 fill_ack_pkt(u32 first, struct rbudp_ack_pkt *ack, size_t max_num_acks)
{
	size_t e = 0;
	u32 curr = first;
	for(; e < max_num_acks;) {
		u32 begin = bitset__scan(&rx_state->received_chunks, curr);
		if(begin == rx_state->received_chunks.num) {
			curr = begin;
			break;
		}
		u32 end = bitset__scan_neg(&rx_state->received_chunks, begin + 1);
		curr = end + 1;
		ack->acks[e].begin = begin;
		ack->acks[e].end = end;
		e++;
	}
	ack->num_acks = e;
	return curr;
}

static seqnr fill_nack_pkt(seqnr first, struct rbudp_ack_pkt *ack, size_t max_num_acks, struct bitset *seqs)
{
	size_t e = 0;
	u32 curr = first;
	for(; e < max_num_acks;) {
		u32 begin = bitset__scan_neg(seqs, curr);
		u32 end = bitset__scan(seqs, begin + 1);
		if(end == seqs->num) {
			break;
		}
		curr = end + 1;
		ack->acks[e].begin = begin;
		ack->acks[e].end = end;
		e++;
	}
	ack->num_acks = e;
	return curr;
}

static void send_eth_frame(int sockfd, void *buf, size_t len)
{
	struct sockaddr_ll addr;
	// Index of the network device
	addr.sll_ifindex = opt_ifindex;
	// Address length
	addr.sll_halen = ETH_ALEN;
	// Destination MAC; extracted from ethernet header
	memcpy(addr.sll_addr, buf, ETH_ALEN);

	ssize_t ret = sendto(sockfd, buf, len, 0, (struct sockaddr *) &addr, sizeof(struct sockaddr_ll));
	if(ret == -1) {
		exit_with_error(errno);
	}
}

static void tx_register_acks(const struct rbudp_ack_pkt *ack, struct sender_state_per_receiver *rcvr)
{
	for(uint16_t e = 0; e < ack->num_acks; ++e) {
		const u32 begin = ack->acks[e].begin;
		const u32 end = ack->acks[e].end;
		if(begin >= end || end > tx_state->total_chunks) {
			return; // Abort
		}
		for(u32 i = begin; i < end; ++i) { // XXX: this can *obviously* be optimized
			bitset__set(&rcvr->acked_chunks, i); // don't need thread-safety here, all updates in same thread
		}
	}
}

static void tx_register_nacks(const struct rbudp_ack_pkt *nack, struct ccontrol_state *cc_state)
{
	for(uint16_t e = 0; e < nack->num_acks; ++e) {
		u32 begin = nack->acks[e].begin;
		u32 end = nack->acks[e].end;
		begin = umax32(begin, cc_state->mi_seq_start);
		end = umin32(end, cc_state->mi_seq_end);
		if(begin >= end || end > cc_state->mi_nacked.num) {
			continue;
		}
		for(u32 i = begin; i < end; ++i) { // XXX: this can *obviously* be optimized
			bitset__set(&cc_state->mi_nacked, i); // don't need thread-safety here, all updates in same thread
		}
	}
}

static void tx_register_pcc_feedback(const struct pcc_feedback *fbk, struct sender_state_per_receiver *rcvr)
{
	if(rcvr->cc_states != NULL) {
		for(u32 i = 0; i < fbk->num_paths; i++) {
			rcvr->cc_states[i].mi_acked_chunks = fbk->pkts[i] - rcvr->cc_states[i].total_acked_chunks;
		}
	}
}

static bool pcc_mi_elapsed(const struct ccontrol_state *cc_state)
{
	unsigned long now = get_nsecs();
	unsigned long dt = now - cc_state->mi_start;
	return cc_state->state != pcc_uninitialized && dt > (cc_state->pcc_mi_duration + cc_state->rtt) * 1e9;
}

static void pcc_monitor()
{
	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		for(u32 cur_path = 0; cur_path < tx_state->receiver[r].num_paths; cur_path++) {
			struct ccontrol_state *cc_state = &tx_state->receiver[r].cc_states[cur_path];
			if(pcc_mi_elapsed(cc_state)) {
				u32 throughput = cc_state->mi_seq_end - cc_state->mi_seq_start; // pkts sent in MI
				throughput = umax32(throughput, 1);
				int diff = (int)(throughput - atomic_load(&cc_state->mi_tx_npkts_monitored));
				if(diff < 0) {
					diff = 0;
				}
				float loss = (float)(cc_state->mi_nacked.num_set + diff) / throughput;
				pcc_control(cc_state, throughput, loss);

				// Start new MI; only safe because no acks are processed during those updates
				cc_state->total_acked_chunks += cc_state->mi_acked_chunks;
				cc_state->mi_acked_chunks = 0;
				ccontrol_start_monitoring_interval(cc_state);
			}
		}
	}
}

bool tx_handle_handshake_reply(const struct rbudp_initial_pkt *initial, struct sender_state_per_receiver *rcvr)
{
	bool updated = false;
	if(initial->path_index < rcvr->num_paths) {
		u64 rtt_estimate = get_nsecs() - initial->timestamp;
		if(atomic_load(&rcvr->paths[initial->path_index].next_handshake_at) != UINT64_MAX) {
			atomic_store(&rcvr->paths[initial->path_index].next_handshake_at, UINT64_MAX);
			if(rcvr->cc_states != NULL && rcvr->cc_states[initial->path_index].rtt == DBL_MAX) {
				ccontrol_update_rtt(&rcvr->cc_states[initial->path_index], rtt_estimate);
				updated = true;
			}
			if(initial->flags & HANDSHAKE_FLAG_SET_RETURN_PATH) {
				rcvr->handshake_rtt = rtt_estimate;
				if(rcvr->cc_states != NULL) {
					u64 now = get_nsecs();
					for(u32 p = 0; p < rcvr->num_paths; p++) {
						if(p != initial->path_index && rcvr->paths[p].enabled) {
							rcvr->paths[p].next_handshake_at = now;
							rcvr->cc_states[p].pcc_mi_duration = DBL_MAX;
							rcvr->cc_states[p].rtt = DBL_MAX;
						}
					}
				}
			}
		}
	}
	return updated;
}

static void tx_recv_control_messages(int sockfd)
{
	struct timeval to = {.tv_sec = 0, .tv_usec = 100};
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

	char buf[ether_size];
	while(!tx_acked_all(tx_state)) {
		const char *payload;
		int payloadlen;
		const struct scionaddrhdr_ipv4 *scionaddrhdr;
		const struct udphdr *udphdr;
		if(recv_rbudp_control_pkt(sockfd, buf, ether_size, &payload, &payloadlen, &scionaddrhdr, &udphdr)) {
			const struct hercules_control_packet *control_pkt = (const struct hercules_control_packet *) payload;
			if((u32) payloadlen < sizeof(control_pkt->type)) {
				debug_printf("control packet too short");
			} else {
				u32 control_pkt_payloadlen = payloadlen - sizeof(control_pkt->type);
				switch(control_pkt->type) {
					case CONTROL_PACKET_TYPE_PCC_FEEDBACK:
						if(control_pkt_payloadlen >= sizeof(control_pkt->payload.pcc_fbk)) {
							struct pcc_feedback fbk;
							memcpy(&fbk, &control_pkt->payload.pcc_fbk, sizeof(control_pkt->payload.pcc_fbk));
							tx_register_pcc_feedback(&fbk,
													 &tx_state->receiver[rcvr_by_src_address(scionaddrhdr, udphdr)]);
						}
						break;
					case CONTROL_PACKET_TYPE_ACK:
						if(control_pkt_payloadlen >= ack__len(&control_pkt->payload.ack)) {
							struct rbudp_ack_pkt ack;
							memcpy(&ack, &control_pkt->payload.ack, ack__len(&control_pkt->payload.ack));
							tx_register_acks(&ack, &tx_state->receiver[rcvr_by_src_address(scionaddrhdr, udphdr)]);
						}
						break;
					case CONTROL_PACKET_TYPE_NACK:
						if(tx_state->receiver[0].cc_states != NULL &&
						   control_pkt_payloadlen >= ack__len(&control_pkt->payload.ack)) {
							struct rbudp_ack_pkt nack;
							// TODO parse this properly
							u8 path_idx = *(((u8 *)control_pkt)-5);
							memcpy(&nack, &control_pkt->payload.ack, ack__len(&control_pkt->payload.ack));
							tx_register_nacks(&nack, &tx_state->receiver[rcvr_by_src_address(scionaddrhdr, udphdr)].cc_states[path_idx]);
						}
						break;
					case CONTROL_PACKET_TYPE_INITIAL:
						if(control_pkt_payloadlen >= sizeof(control_pkt->payload.initial)) {
							struct rbudp_initial_pkt initial;
							memcpy(&initial, &control_pkt->payload.initial, sizeof(control_pkt->payload.initial));
							int rcvr_idx = rcvr_by_src_address(scionaddrhdr, udphdr);
							struct sender_state_per_receiver *receiver = &tx_state->receiver[rcvr_idx];
							if(tx_handle_handshake_reply(&initial, receiver)) {
								debug_printf("[receiver %d] [path %d] handshake_rtt: %fs, MI: %fs", rcvr_idx,
											 initial.path_index, receiver->cc_states[initial.path_index].rtt,
											 receiver->cc_states[initial.path_index].pcc_mi_duration);
							}
						}
						break;
					default:
						debug_printf("received a control packet of unknown type %d", control_pkt->type);
				}
			}
		}

		if(tx_state->receiver[0].cc_states) {
			pcc_monitor();
		}
	}
}

static bool tx_handle_cts(const char *cts, size_t payloadlen, u32 rcvr)
{
	const struct hercules_control_packet *control_pkt = (const struct hercules_control_packet *)cts;
	if(payloadlen < sizeof(control_pkt->type) + sizeof(control_pkt->payload.ack.num_acks)) {
		return false;
	}
	if(control_pkt->type == CONTROL_PACKET_TYPE_ACK && control_pkt->payload.ack.num_acks == 0) {
		tx_state->receiver[rcvr].cts_received = true;
		return true;
	}
	return false;
}

static bool tx_await_cts(int sockfd)
{
	// count received CTS
	u32 received = 0;
	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		if(tx_state->receiver[r].cts_received) {
			received++;
		}
	}

	// Set 20 second timeout on the socket, wait for receiver to get ready
	struct timeval to = {.tv_sec = 60, .tv_usec = 0};
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

	char buf[ether_size];
	const char *payload;
	int payloadlen;
	const struct scionaddrhdr_ipv4 *scionaddrhdr;
	const struct udphdr *udphdr;
	for(u64 start = get_nsecs(); start + 20e9l > get_nsecs();) {
		if(recv_rbudp_control_pkt(sockfd, buf, ether_size, &payload, &payloadlen, &scionaddrhdr, &udphdr)) {
			if(tx_handle_cts(payload, payloadlen, rcvr_by_src_address(scionaddrhdr, udphdr))) {
				received++;
				if(received >= tx_state->num_receivers) {
					return true;
				}
			}
		}
	}
	return false;
}

static void tx_send_handshake_ack(int sockfd, u32 rcvr)
{
	char buf[ether_size];
	struct hercules_path *path = &tx_state->receiver[rcvr].paths[0];
	void *rbudp_pkt = mempcpy(buf, path->headers[0].header, path->headerlen);

	struct rbudp_ack_pkt ack;
	ack.num_acks = 0;

	fill_rbudp_pkt(rbudp_pkt, UINT_MAX, PCC_NO_PATH, 0, (char *) &ack, ack__len(&ack), path->payloadlen);
	stitch_checksum(path, path->headers[0].checksum, buf);

	send_eth_frame(sockfd, buf, path->framelen);
	atomic_fetch_add(&tx_npkts, 1);
}

static bool tx_await_rtt_ack(int sockfd, const struct scionaddrhdr_ipv4 **scionaddrhdr, const struct udphdr **udphdr)
{
	const struct scionaddrhdr_ipv4 *scionaddrhdr_fallback;
	if(scionaddrhdr == NULL) {
		scionaddrhdr = &scionaddrhdr_fallback;
	}

	const struct udphdr *udphdr_fallback;
	if(udphdr == NULL) {
		udphdr = &udphdr_fallback;
	}

	// Set 1 second timeout on the socket
	struct timeval to = {.tv_sec = 1, .tv_usec = 0};
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

	char buf[ether_size];
	const char *payload;
	int payloadlen;
	if(recv_rbudp_control_pkt(sockfd, buf, ether_size, &payload, &payloadlen, scionaddrhdr, udphdr)) {
		struct rbudp_initial_pkt parsed_pkt;
		u32 rcvr = rcvr_by_src_address(*scionaddrhdr, *udphdr);
		if(rbudp_parse_initial(payload, payloadlen, &parsed_pkt)) {
			if(rcvr < tx_state->num_receivers && tx_state->receiver[rcvr].handshake_rtt == 0) {
				tx_state->receiver[rcvr].handshake_rtt = (u64) (get_nsecs() - parsed_pkt.timestamp);
				if(parsed_pkt.filesize != tx_state->filesize ||
				   parsed_pkt.chunklen != tx_state->chunklen) {
					debug_printf("Receiver disagrees "
								 "on transfer parameters:\n"
								 "filesize: %llu\nchunklen: %u",
								 parsed_pkt.filesize,
								 parsed_pkt.chunklen);
					return false;
				}
				tx_send_handshake_ack(sockfd, rcvr);
			}
			return true;
		} else {
			tx_handle_cts(payload, payloadlen, rcvr);
		}
	}
	return false;
}

static void
tx_send_initial(int sockfd, const struct hercules_path *path, size_t filesize, u32 chunklen, unsigned long timestamp,
				u32 path_index, bool set_return_path)
{
	char buf[ether_size];
	void *rbudp_pkt = mempcpy(buf, path->headers[0].header, path->headerlen);

	struct hercules_control_packet pld = {
			.type = CONTROL_PACKET_TYPE_INITIAL,
			.payload.initial = {
				.filesize = filesize,
				.chunklen = chunklen,
				.timestamp = timestamp,
				.path_index = path_index,
				.flags = set_return_path ? HANDSHAKE_FLAG_SET_RETURN_PATH : 0,
			},
	};
	fill_rbudp_pkt(rbudp_pkt, UINT_MAX, PCC_NO_PATH, 0, (char *) &pld, sizeof(pld.type) + sizeof(pld.payload.initial), path->payloadlen);
	stitch_checksum(path, path->headers[0].checksum, buf);

	send_eth_frame(sockfd, buf, path->framelen);
	atomic_fetch_add(&tx_npkts, 1);
}

static bool tx_handshake(int sockfd)
{
	bool succeeded[tx_state->num_receivers];
	memset(succeeded, 0, sizeof(succeeded));
	for(u64 start = get_nsecs(); start >= get_nsecs() - tx_handshake_timeout;) {
		int await = 0;
		for(u32 r = 0; r < tx_state->num_receivers; r++) {
			if(!succeeded[r]) {
				unsigned long timestamp = get_nsecs();
				tx_send_initial(sockfd, &tx_state->receiver[r].paths[0], tx_state->filesize, tx_state->chunklen,
								timestamp, 0, true);
				await++;
			}
		}

		const struct scionaddrhdr_ipv4 *scionaddrhdr;
		const struct udphdr *udphdr;
		while(tx_await_rtt_ack(sockfd, &scionaddrhdr, &udphdr)) {
			u32 rcvr = rcvr_by_src_address(scionaddrhdr, udphdr);
			if(rcvr < tx_state->num_receivers && !succeeded[rcvr]) {
				tx_state->receiver[rcvr].paths[0].next_handshake_at = UINT64_MAX;
				succeeded[rcvr] = true;
				await--;
				if(await == 0) {
					return true;
				}
			}
		}
		debug_printf("Timeout, retry.");
	}
	fprintf(stderr, "ERR: timeout during handshake. Gave up after %.0f seconds.\n", tx_handshake_timeout / 1e9);
	return false;
}

static void stitch_checksum(const struct hercules_path *path, u16 precomputed_checksum, char *pkt)
{
	chk_input chk_input_s;
	chk_input *chksum_struc = init_chk_input(&chk_input_s, 2);
	assert(chksum_struc);
	char *payload = pkt + path->headerlen;
	precomputed_checksum = ~precomputed_checksum; // take one complement of precomputed checksum
	chk_add_chunk(chksum_struc, (u8 *) &precomputed_checksum, 2); // add precomputed header checksum
	chk_add_chunk(chksum_struc, (u8 *) payload, path->payloadlen); // add payload
	u16 pkt_checksum = checksum(chksum_struc);

	mempcpy(payload - 2, &pkt_checksum, sizeof(pkt_checksum));
}

static void
rx_handle_initial(int sockfd, struct rbudp_initial_pkt *initial, const char *buf, const char *payload, int payloadlen);

static void rx_receive_batch(struct xsk_socket_info *xsk)
{
	u32 idx_rx = 0, idx_fq = 0;
	int ignored = 0;

	// XXX: restricting to receiving BATCH_SIZE here seems unnecessary. Change to SIZE_MAX?
	size_t rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
	if(!rcvd)
		return;

	size_t reserved = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	while(reserved != rcvd) {
		reserved = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
		if(!running)
			return;
	}

	for(size_t i = 0; i < rcvd; i++) {
		u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->addr;
		u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->len;
		const char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
		const char *rbudp_pkt = parse_pkt_fast_path(pkt, len, true, UINT32_MAX);
		if(rbudp_pkt) {
			if(!handle_rbudp_data_pkt(rbudp_pkt, len - (rbudp_pkt - pkt))) {
				struct rbudp_initial_pkt initial;
				if(rbudp_parse_initial(rbudp_pkt + rbudp_headerlen, len, &initial)) {
					rx_handle_initial(rx_state->control_sock_fd, &initial, pkt, rbudp_pkt,
									  (int) len - (int) (rbudp_pkt - pkt));
				} else {
					ignored++;
				}
			}
		} else {
			ignored++;
		}
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = addr;
	}
	xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
	xsk_ring_cons__release(&xsk->rx, rcvd);
	atomic_fetch_add(&rx_npkts, (rcvd - ignored));
}

static void rate_limit_tx(void)
{
	if(prev_tx_npkts_queued + RATE_LIMIT_CHECK > tx_npkts_queued)
		return;

	u64 now = get_nsecs();
	u64 dt = now - prev_rate_check;

	u64 d_npkts = tx_npkts_queued - prev_tx_npkts_queued;

	dt = umin64(dt, 1);
	u32 tx_pps = d_npkts * 1000000000. / dt;

	if(tx_pps > tx_state->rate_limit) {
		u64 min_dt = (d_npkts * 1000000000. / tx_state->rate_limit);

		// Busy wait implementation
		while(now < prev_rate_check + min_dt) {
			now = get_nsecs();
		}
	}

	prev_rate_check = now;
	prev_tx_npkts_queued = tx_npkts_queued;
}

// Fill packet with n bytes from data and pad with zeros to payloadlen.
static void fill_rbudp_pkt(void *rbudp_pkt, u32 chunk_idx, u8 path_idx, seqnr sequence_number, const char *data,
						   size_t n, size_t payloadlen)
{
	void *rbudp_path_idx = mempcpy(rbudp_pkt, &chunk_idx, sizeof(chunk_idx));
	void *rbudp_seqnr = mempcpy(rbudp_path_idx, &path_idx, sizeof(path_idx));
	void *rbudp_payload = mempcpy(rbudp_seqnr, &sequence_number, sizeof(sequence_number));
	void *start_pad = mempcpy(rbudp_payload, data, n);
	if(sizeof(chunk_idx) + sizeof(path_idx) + n < payloadlen) {
		memset(start_pad, 0, payloadlen - sizeof(chunk_idx) - sizeof(path_idx) - n);
	}
}


static pthread_mutex_t path_lock;

void acquire_path_lock()
{
	pthread_mutex_lock(&path_lock);
}

void free_path_lock()
{
	pthread_mutex_unlock(&path_lock);
}

void push_hercules_tx_paths()
{
	if(tx_state != NULL) {
		debug_printf("Got new paths!");
		tx_state->has_new_paths = true;
	}
}

void allocate_path_headers(struct hercules_path *path, int num_headers) {
	// this function is only called in non-performance critical paths, hence we have the time to manage memory
	if (path->num_headers < num_headers) {
		if (path->headers != NULL) {
			free(path->headers); // this should not be necessary: the number of header versions per destination should
			// not change, as the number of IP addresses per destination is fixed at startup
		}
		path->headers = calloc(num_headers, sizeof(*path->headers));
	} else if(num_headers == 0) {
		debug_printf("no header versions given, abort");
		exit_with_error(ENODATA);
	}
}

static void update_hercules_tx_paths(void)
{
	acquire_path_lock();
	tx_state->has_new_paths = false;
	u64 now = get_nsecs();
	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		struct sender_state_per_receiver *receiver = &tx_state->receiver[r];
		receiver->num_paths = tx_state->shd_num_paths[r];

		bool replaced_return_path = false;
		for(u32 p = 0; p < receiver->num_paths; p++) {
			struct hercules_path *shd_path = &tx_state->shd_paths[r * tx_state->max_paths_per_rcvr + p];
			if(!shd_path->enabled && p == receiver->return_path_idx) {
				receiver->return_path_idx++;
			}
			if(shd_path->replaced) {
				shd_path->replaced = false;
				// assert that chunk length fits into packet with new header
				if(shd_path->payloadlen < (int) tx_state->chunklen + rbudp_headerlen) {
					fprintf(stderr, "cannot use path %d for receiver %d: header too big, chunk does not fit into payload\n", p, r);
					receiver->paths[p].enabled = false;
					continue;
				}
				struct hercules_path_header *old_headers = receiver->paths[p].headers;
				memcpy(&receiver->paths[p], shd_path, sizeof(struct hercules_path));
				shd_path->headers = old_headers; // this pushes the memory management for struct hercules_path_header to
				// the Go part which is less performance critical

				atomic_store(&receiver->paths[p].next_handshake_at, UINT64_MAX); // by default do not send a new handshake
				if(p == receiver->return_path_idx) {
					atomic_store(&receiver->paths[p].next_handshake_at, now); // make sure handshake_rtt is adapted
					// don't trigger RTT estimate on other paths, as it will be triggered by the ACK on the new return path
					replaced_return_path = true;
				}
				// reset PCC state
				if(!replaced_return_path && receiver->cc_states != NULL) {
					terminate_ccontrol(&receiver->cc_states[p]);
					continue_ccontrol(&receiver->cc_states[p]);
					atomic_store(&receiver->paths[p].next_handshake_at, now); // make sure mi_duration is set
				}
			} else {
				if(p == receiver->return_path_idx) {
					atomic_store(&receiver->paths[p].next_handshake_at, now); // make sure handshake_rtt is adapted
					// don't trigger RTT estimate on other paths, as it will be triggered by the ACK on the new return path
					replaced_return_path = true;
				}
				if(receiver->cc_states != NULL && receiver->paths[p].enabled != shd_path->enabled) {
					if(shd_path->enabled) { // reactivate PCC
						if(receiver->cc_states != NULL) {
							double rtt = receiver->cc_states[p].rtt;
							double mi_duration = receiver->cc_states[p].pcc_mi_duration;
							continue_ccontrol(&receiver->cc_states[p]);
							receiver->cc_states[p].rtt = rtt;
							receiver->cc_states[p].pcc_mi_duration = mi_duration;
						}
					} else { // deactivate PCC
						terminate_ccontrol(&receiver->cc_states[p]);
					}
				}
				receiver->paths[p].enabled = shd_path->enabled;
			}
		}
	}
	free_path_lock();
}

void send_path_handshakes()
{
	u64 now = get_nsecs();
	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		struct sender_state_per_receiver *rcvr = &tx_state->receiver[r];
		for(u32 p = 0; p < rcvr->num_paths; p++) {
			struct hercules_path *path = &rcvr->paths[p];
			if(path->enabled) {
				u64 handshake_at = atomic_load(&path->next_handshake_at);
				if(handshake_at < now) {
					if(atomic_compare_exchange_strong(&path->next_handshake_at, &handshake_at, now + PATH_HANDSHAKE_TIMEOUT_NS)) {
						tx_send_initial(tx_state->control_socket_fd, path, tx_state->filesize, tx_state->chunklen,
								get_nsecs(), p, p == rcvr->return_path_idx);
					}
				}
			}
		}
	}
}


/*!
 * @function	produce_frame
 * @abstract	Fill an entry in the sender transmission ring with frame frame_nb and
 *		return the corresponding umem buffer address.
 * @param	xsk		the socket
 * @param	frame_nb	the frame number of the frame being put in the tx ring
 * @param	prod_tx_idx	index in the tx ring where the frame is being inserted
 * @param	framelen	size of the frame, smaller than XSK_UMEM__DEFAULT_FRAME_SIZE
 * @result	A pointer to the umem buffer corresponding to the frame
*/
static char *produce_frame(struct xsk_socket_info *xsk, u32 frame_nb, u32 prod_tx_idx, size_t framelen)
{
	const u64 addr = frame_nb << XSK_UMEM__DEFAULT_FRAME_SHIFT;
	xsk_ring_prod__tx_desc(&xsk->tx, prod_tx_idx)->addr = addr;
	xsk_ring_prod__tx_desc(&xsk->tx, prod_tx_idx)->len = framelen;
	char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
	return pkt;
}

static void submit_batch(struct xsk_socket_info *xsk, u32 *frame_nb, u32 i)
{
	xsk_ring_prod__submit(&xsk->tx, i);

	xsk->outstanding_tx += i;
	*frame_nb += i;
	if(*frame_nb + SEND_QUEUE_ENTRIES_PER_UNIT > NUM_FRAMES) { // Wrap around if next batch would overflow
		*frame_nb = 0;
	}

	kick_tx(xsk);
	pop_completion_ring(xsk);
}

static inline void tx_handle_send_queue_unit(struct xsk_socket_info *xsk, struct send_queue_unit *unit, u32 *frame_nb,
		u32 *random_seed) {
	u32 num_chunks_in_unit;
	for(num_chunks_in_unit = 0; num_chunks_in_unit < SEND_QUEUE_ENTRIES_PER_UNIT; num_chunks_in_unit++) {
		if(unit->paths[num_chunks_in_unit] == UINT8_MAX) {
			break;
		}
	}

	u32 idx;
	while(xsk_ring_prod__reserve(&xsk->tx, num_chunks_in_unit, &idx) != num_chunks_in_unit) {
		kick_tx(xsk); // XXX: investigate how sender can still starve without this, it seems it should NOT be necessary
		// While we're waiting, consume completion ring to avoid that the kernel
		// could starve on completion ring slots. (ring is smaller than number of
		// frames)
		pop_completion_ring(xsk);
	}

	for(u32 i = 0; i < num_chunks_in_unit; i++) {
		const struct sender_state_per_receiver *receiver = &tx_state->receiver[unit->rcvr[i]];
		const struct hercules_path *path = &receiver->paths[unit->paths[i]];
		const u32 chunk_idx = unit->chunk_idx[i];
		const size_t chunk_start = (size_t) chunk_idx * tx_state->chunklen;
		const size_t len = umin64(tx_state->chunklen, tx_state->filesize - chunk_start);
		u32 hdr_idx = rand_r(random_seed) % path->num_headers; // pick random header version

		void *pkt = produce_frame(xsk, *frame_nb + i, idx + i, path->framelen);
		void *rbudp_pkt = mempcpy(pkt, path->headers[hdr_idx].header, path->headerlen);
		u8 track_path = PCC_NO_PATH; // put path_idx iff PCC is enabled
		seqnr sequence_number = 0;
		if(receiver->cc_states != NULL) {
			track_path = unit->paths[i];
			sequence_number = atomic_fetch_add(&receiver->cc_states[unit->paths[i]].last_sequence_number, 1);
		}
		fill_rbudp_pkt(rbudp_pkt, chunk_idx, track_path, sequence_number, tx_state->mem + chunk_start, len, path->payloadlen);
		stitch_checksum(path, path->headers[hdr_idx].checksum, pkt);
	}

	submit_batch(xsk, frame_nb, num_chunks_in_unit);
}

static void produce_batch(const u8 *path_by_rcvr, const u32 *chunks, const u8 *rcvr_by_chunk, u32 num_chunks)
{
	u32 chk;
	u32 num_chunks_in_unit;
	struct send_queue_unit *unit = NULL;
	for(chk = 0; chk < num_chunks; chk++) {
		if(unit == NULL) {
			unit = send_queue_reserve(&send_queue);
			num_chunks_in_unit = 0;
			if(unit == NULL) {
				chk--; // retry with same chunk
				continue;
			}
		}

		unit->rcvr[num_chunks_in_unit] = rcvr_by_chunk[chk];
		unit->paths[num_chunks_in_unit] = path_by_rcvr[rcvr_by_chunk[chk]];
		unit->chunk_idx[num_chunks_in_unit] = chunks[chk];

		num_chunks_in_unit++;
		if(num_chunks_in_unit == SEND_QUEUE_ENTRIES_PER_UNIT || chk == num_chunks-1) {
			if(num_chunks_in_unit < SEND_QUEUE_ENTRIES_PER_UNIT) {
				unit->paths[num_chunks_in_unit] = UINT8_MAX;
			}
			send_queue_push(&send_queue);
			unit = NULL;
		}
	}
}

static void tx_send_p(void *arg) {
	struct xsk_socket_info *xsk = arg;

	struct send_queue_unit unit;
	send_queue_pop_wait(&send_queue, &unit);
	u32 frame_nb = 0;
	u32 random_seed = (u32) (size_t) arg + pthread_self() + (u32) get_nsecs();
	while(true) {
		tx_handle_send_queue_unit(xsk, &unit, &frame_nb, &random_seed);
		if(!send_queue_pop(&send_queue, &unit)) { // queue currently empty
			while(!send_queue_pop(&send_queue, &unit)) {
				// whenever we're waiting, claim frames back
				pop_completion_ring(xsk);
			}
		}
	}
}

// Collect path rate limits
u32 compute_max_chunks_per_rcvr(u32 *max_chunks_per_rcvr)
{
	u32 total_chunks = 0;
	u64 now = get_nsecs();

	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		if(!tx_state->receiver[r].paths[tx_state->receiver[r].path_index].enabled) {
			continue; // if a receiver does not have any enabled paths, we can actually end up here ... :(
		}
		if(tx_state->receiver[r].cc_states != NULL) { // use PCC
			struct ccontrol_state *cc_state = &tx_state->receiver[r].cc_states[tx_state->receiver[r].path_index];
			max_chunks_per_rcvr[r] = umin32(BATCH_SIZE, ccontrol_can_send_npkts(cc_state, now));
		} else { // no path-based limit
			max_chunks_per_rcvr[r] = BATCH_SIZE;
		}
		total_chunks += max_chunks_per_rcvr[r];
	}
	return total_chunks;
}

// exclude receivers that have completed the current iteration
u32 exclude_finished_receivers(u32 *max_chunks_per_rcvr, u32 total_chunks)
{
	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		if(tx_state->receiver[r].finished) {
			total_chunks -= max_chunks_per_rcvr[r];
			max_chunks_per_rcvr[r] = 0;
		}
	}
	return total_chunks;
}

// Send a total max of BATCH_SIZE
u32 shrink_sending_rates(u32 *max_chunks_per_rcvr, u32 total_chunks)
{
	if(total_chunks > BATCH_SIZE) {
		u32 new_total_chunks = 0; // due to rounding errors, we need to aggregate again
		for(u32 r = 0; r < tx_state->num_receivers; r++) {
			max_chunks_per_rcvr[r] = max_chunks_per_rcvr[r] * BATCH_SIZE / total_chunks;
			new_total_chunks += max_chunks_per_rcvr[r];
		}
		return new_total_chunks;
	}
	return total_chunks;
}

void prepare_rcvr_paths(u8 *rcvr_path)
{
	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		rcvr_path[r] = tx_state->receiver[r].path_index;
	}
}

void iterate_paths()
{
	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		struct sender_state_per_receiver *receiver = &tx_state->receiver[r];
		if(receiver->num_paths == 0) {
			continue;
		}
		u32 prev_path_index = receiver->path_index; // we need this to break the loop if all paths are disabled
		if(prev_path_index >= receiver->num_paths) {
			prev_path_index = 0;
		}
		do {
			receiver->path_index = (receiver->path_index + 1) % receiver->num_paths;
		} while(!receiver->paths[receiver->path_index].enabled && receiver->path_index != prev_path_index);
	}
}

static void terminate_cc(const struct sender_state_per_receiver *receiver)
{
	for(u32 i = 0; i < receiver->num_paths; i++) {
		terminate_ccontrol(&receiver->cc_states[i]);
	}
}

static void kick_cc()
{
	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		if(tx_state->receiver[r].finished) {
			continue;
		}
		for(u32 p = 0; p < tx_state->receiver[r].num_paths; p++) {
			kick_ccontrol(&tx_state->receiver[r].cc_states[p]);
		}
	}
}

// Select batch of un-ACKed chunks for (re)transmit:
// Batch ends if an un-ACKed chunk is encountered for which we should keep
// waiting a bit before retransmit.
//
// If a chunk can not yet be send, because we need to wait for an ACK, wait_until
// is set to the timestamp by which that ACK should arrive. Otherwise, wait_until
// is not modified.
static u32 prepare_rcvr_chunks(struct sender_state_per_receiver *rcvr, u32 *chunks, u8 *chunk_rcvr, const u64 now,
		u32 rcvr_idx, u64 *wait_until, u32 num_chunks)
{
	u32 num_chunks_prepared = 0;
	u32 chunk_idx = rcvr->prev_chunk_idx;
	for(; num_chunks_prepared < num_chunks; num_chunks_prepared++) {
		chunk_idx = bitset__scan_neg(&rcvr->acked_chunks, chunk_idx);
		if(chunk_idx == tx_state->total_chunks) {
			if(rcvr->prev_chunk_idx == 0) { // this receiver has finished
				rcvr->finished = true;
				break;
			}

			// switch round for this receiver:
			debug_printf("Receiver %d switches to next round", rcvr_idx);

			chunk_idx = 0;
			rcvr->prev_round_start = rcvr->prev_round_end;
			rcvr->prev_round_end = get_nsecs();
			u64 prev_round_dt = rcvr->prev_round_end - rcvr->prev_round_start;
			rcvr->prev_slope = (prev_round_dt + tx_state->total_chunks - 1) / tx_state->total_chunks; // round up
			rcvr->ack_wait_duration = 3 * (ACK_RATE_TIME_MS * 1000000UL + rcvr->handshake_rtt);
			break;
		}

		const u64 prev_transmit = umin64(rcvr->prev_round_start + rcvr->prev_slope * chunk_idx, rcvr->prev_round_end);
		const u64 ack_due = prev_transmit + rcvr->ack_wait_duration; // 0 for first round
		if(now >= ack_due) { // add the chunk to the current batch
			*chunks = chunk_idx++;
			*chunk_rcvr = rcvr_idx;
			chunks++;
			chunk_rcvr++;
		} else { // no chunk to send - skip this receiver in the current batch
			(*wait_until) = ack_due;
			break;
		}
	}
	rcvr->prev_chunk_idx = chunk_idx;
	return num_chunks_prepared;
}

/**
 * Transmit and retransmit chunks that have not been ACKed.
 * For each retransmit chunk, wait (at least) one round trip time for the ACK to arrive.
 * For large files transfers, this naturally allows to start retransmitting chunks at the beginning
 * of the file, while chunks of the previous round at the end of the file are still in flight.
 *
 * Transmission to different receivers is interleaved in a round-robin fashion.
 * Transmission through different paths is batched (i.e. use the same path within a batch) to prevent the receiver from
 * ACKing individual chunks.
 *
 * The rounds of different receivers are isolated from each other.
 *
 * The estimates for the ACK-arrival time dont need to be accurate for correctness, i.e. regardless
 * of how bad our estimate is, all chunks will be (re-)transmitted eventually.
 *	 - if we *under-estimate* the RTT, we may retransmit chunks unnecessarily
 *	   - waste bandwidth, waste sender disk reads & CPU time, waste receiver CPU time
 *	   - potentially increase overall transmit time because necessary retransmit may be delayed by
 *	     wasted resources
 *	 - if we *over-estimate* the RTT, we wait unnecessarily
 *		 This is only constant overhead per retransmit round, independent of number of packets or send
 *		 rate.
 * Thus it seems preferrable to *over-estimate* the ACK-arrival time.
 *
 * To avoid recording transmit time per chunk, only record start and end time of a transmit round
 * and linearly interpolate for each receiver separately.
 * This assumes a uniform send rate and that chunks that need to be retransmitted (i.e. losses)
 * occur uniformly.
 */
static void tx_only()
{
	debug_printf("Start transmit round for all receivers");
	prev_rate_check = get_nsecs();
	u32 finished_count = 0;

	u32 chunks[BATCH_SIZE];
	u8 chunk_rcvr[BATCH_SIZE];
	u32 max_chunks_per_rcvr[tx_state->num_receivers];

	while(finished_count < tx_state->num_receivers) {
		send_path_handshakes();
		u64 next_ack_due = 0;
		u32 num_chunks_per_rcvr[tx_state->num_receivers];
		memset(num_chunks_per_rcvr, 0, sizeof(num_chunks_per_rcvr));

		// in each iteration, we send packets on a single path to each receiver
		// collect the rate limits for each active path
		u32 total_chunks = compute_max_chunks_per_rcvr(max_chunks_per_rcvr);
		total_chunks = exclude_finished_receivers(max_chunks_per_rcvr, total_chunks);

		if(total_chunks == 0) { // we hit the rate limits on every path; switch paths
			if(tx_state->has_new_paths) {
				update_hercules_tx_paths();
			}
			iterate_paths();
			continue;
		}

		// sending rates might add up to more than BATCH_SIZE, shrink proportionally, if needed
		shrink_sending_rates(max_chunks_per_rcvr, total_chunks);

		const u64 now = get_nsecs();
		u32 num_chunks = 0;
		for(u32 r = 0; r < tx_state->num_receivers; r++) {
			struct sender_state_per_receiver *rcvr = &tx_state->receiver[r];
			if(!rcvr->finished) {
				u64 ack_due = 0;
				// for each receiver, we prepare up to max_chunks_per_rcvr[r] chunks to send
				u32 cur_num_chunks = prepare_rcvr_chunks(&tx_state->receiver[r], &chunks[num_chunks],
											  &chunk_rcvr[num_chunks], now, r, &ack_due, max_chunks_per_rcvr[r]);
				num_chunks += cur_num_chunks;
				num_chunks_per_rcvr[r] += cur_num_chunks;
				if(rcvr->finished) {
					finished_count++;
					if(rcvr->cc_states) {
						terminate_cc(rcvr);
						kick_cc();
					}
				} else {
					// only wait for the nearest ack
					if(next_ack_due) {
						if(next_ack_due > ack_due) {
							next_ack_due = ack_due;
						}
					} else {
						next_ack_due = ack_due;
					}
				}
			}
		}

		if(num_chunks > 0) {
			u8 rcvr_path[tx_state->num_receivers];
			prepare_rcvr_paths(rcvr_path);
			produce_batch(rcvr_path, chunks, chunk_rcvr, num_chunks);
			tx_npkts_queued += num_chunks;
			rate_limit_tx();

			// update book-keeping
			for(u32 r = 0; r < tx_state->num_receivers; r++) {
				struct sender_state_per_receiver *receiver = &tx_state->receiver[r];
				u32 path_idx = tx_state->receiver[r].path_index;
				if(receiver->cc_states != NULL) {
					struct ccontrol_state *cc_state = &receiver->cc_states[path_idx];
					atomic_fetch_add(&cc_state->mi_tx_npkts, num_chunks_per_rcvr[r]);
					if(cc_state->mi_start + (u64)((cc_state->pcc_mi_duration) * 1e9) >= now) {
						atomic_fetch_add(&cc_state->mi_tx_npkts_monitored, num_chunks_per_rcvr[r]);
					}
				}
			}
		}

		if(tx_state->has_new_paths) {
			update_hercules_tx_paths();
		}
		iterate_paths();

		if(now < next_ack_due) {
			sleep_until(next_ack_due);
		}
	}
}

static void
init_tx_state(size_t filesize, int chunklen, int max_rate_limit, char *mem, const struct hercules_app_addr *dests,
			  struct hercules_path *paths, u32 num_dests, const int *num_paths, u32 max_paths_per_dest,
			  int control_socket_fd)
{
	u64 total_chunks = (filesize + chunklen - 1) / chunklen;
	if(total_chunks >= UINT_MAX) {
		fprintf(stderr, "File too big, not enough chunks available (chunks needed: %llu, chunks available: %u)\n",
				total_chunks, UINT_MAX - 1);
		exit(1);
	}

	tx_state = calloc(1, sizeof(*tx_state));
	tx_state->filesize = filesize;
	tx_state->chunklen = chunklen;
	tx_state->total_chunks = total_chunks;
	tx_state->mem = mem;
	tx_state->control_socket_fd = control_socket_fd;
	tx_state->rate_limit = max_rate_limit;
	tx_state->start_time = 0;
	tx_state->end_time = 0;
	tx_state->num_receivers = num_dests;
	tx_state->receiver = calloc(num_dests, sizeof(*tx_state->receiver));
	tx_state->max_paths_per_rcvr = max_paths_per_dest;
	tx_state->shd_paths = paths;
	tx_state->shd_num_paths = num_paths;
	tx_state->has_new_paths = false;

	for(u32 d = 0; d < num_dests; d++) {
		struct sender_state_per_receiver *receiver = &tx_state->receiver[d];
		bitset__create(&receiver->acked_chunks, tx_state->total_chunks);
		receiver->path_index = 0;
		receiver->handshake_rtt = 0;
		receiver->num_paths = num_paths[d];
		receiver->paths = calloc(tx_state->max_paths_per_rcvr, sizeof(struct hercules_path));
		receiver->addr = dests[d];
		receiver->cts_received = false;
	}
	update_hercules_tx_paths();
}

static void destroy_tx_state()
{
	for(u32 d = 0; d < tx_state->num_receivers; d++) {
		struct sender_state_per_receiver *receiver = &tx_state->receiver[d];
		bitset__destroy(&receiver->acked_chunks);
		free(receiver->paths);
	}
	free(tx_state);
}

static struct receiver_state *make_rx_state(size_t filesize, int chunklen, int control_sock_fd)
{
	struct receiver_state *r;
	r = calloc(1, sizeof(*r));
	r->filesize = filesize;
	r->chunklen = chunklen;
	r->total_chunks = (filesize + chunklen - 1) / chunklen;
	bitset__create(&r->received_chunks, r->total_chunks);
	r->start_time = 0;
	r->end_time = 0;
	r->handshake_rtt = 0;
	r->control_sock_fd = control_sock_fd;
	return r;
}

static char *rx_mmap(const char *pathname, size_t filesize)
{
	int ret;
	ret = unlink(pathname);
	if(ret && errno != ENOENT) {
		exit_with_error(errno);
	}
	int f = open(pathname, O_RDWR | O_CREAT | O_EXCL, 0664);
	if(f == -1) {
		exit_with_error(errno);
	}
	ret = fallocate(f, 0, 0, filesize); // Will fail on old filesystems (ext3)
	if(ret) {
		exit_with_error(errno);
	}
	char *mem = mmap(NULL, filesize, PROT_WRITE, MAP_SHARED, f, 0);
	if(mem == MAP_FAILED) {
		exit_with_error(errno);
	}
	close(f);
	// fault and dirty the pages
	// This may be a terrible idea if filesize is larger than the available memory.
	// Note: MAP_POPULATE does NOT help when preparing for _writing_.
	int pagesize = getpagesize();
	for(ssize_t i = (ssize_t) filesize - 1; i > 0; i -= pagesize) {
		mem[i] = 0;
	}
	return mem;
}

static bool rbudp_parse_initial(const char *pkt, size_t len, struct rbudp_initial_pkt *parsed_pkt)
{
	struct hercules_control_packet control_pkt;
	memcpy(&control_pkt, pkt, len);
	if(control_pkt.type != CONTROL_PACKET_TYPE_INITIAL) {
		return false;
	}
	if(len < sizeof(control_pkt.type) + sizeof(*parsed_pkt)) {
		return false;
	}
	memcpy(parsed_pkt, &control_pkt.payload.initial, sizeof(*parsed_pkt));
	return true;
}

static bool rx_get_reply_path(struct hercules_path *path, struct hercules_path_header *path_header)
{
	// Get reply path for sending ACKs:
	//
	// XXX: race reading from shared mem.
	// Try to make a quick copy to at least limit the carnage.
	if(!rx_state) {
		debug_printf("ERROR: invalid rx_state");
		return false;
	}
	int rx_sample_len = rx_state->rx_sample_len;
	assert(rx_sample_len > 0);
	assert(rx_sample_len <= XSK_UMEM__DEFAULT_FRAME_SIZE);
	char rx_sample_buf[XSK_UMEM__DEFAULT_FRAME_SIZE];
	memcpy(rx_sample_buf, rx_state->rx_sample_buf, rx_sample_len);

	// prepare hercules_path
	path->headers = path_header;
	path->num_headers = 1;

	int ret = HerculesGetReplyPath(rx_sample_buf, rx_sample_len, path);
	if(ret) {
		return false;
	}
	return true;
}

static void rx_send_rtt_ack(int sockfd, struct rbudp_initial_pkt *pld)
{
	struct hercules_path path;
	struct hercules_path_header path_header;
	if(!rx_get_reply_path(&path, &path_header)) {
		return;
	}

	char buf[ether_size];
	void *rbudp_pkt = mempcpy(buf, path.headers[0].header, path.headerlen);

	struct hercules_control_packet control_pkt = {
			.type = CONTROL_PACKET_TYPE_INITIAL,
			.payload.initial = *pld,
	};

	fill_rbudp_pkt(rbudp_pkt, UINT_MAX, PCC_NO_PATH, 0, (char *) &control_pkt,
				   sizeof(control_pkt.type) + sizeof(control_pkt.payload.initial), path.payloadlen);
	stitch_checksum(&path, path.headers[0].checksum, buf);

	send_eth_frame(sockfd, buf, path.framelen);
	atomic_fetch_add(&tx_npkts, 1);
}

static void
rx_handle_initial(int sockfd, struct rbudp_initial_pkt *initial, const char *buf, const char *payload, int payloadlen)
{
	const int headerlen = (int) (payload - buf);
	if(initial->flags & HANDSHAKE_FLAG_SET_RETURN_PATH) {
		set_rx_sample(rx_state, buf, headerlen + payloadlen);
	}

	rx_send_rtt_ack(sockfd, initial); // echo back initial pkt to ACK filesize
	rx_state->cts_sent_at = get_nsecs();
}

static bool rx_accept(int sockfd)
{
	char buf[ether_size];
	while(true) { // Wait for well formed startup packet
		const char *payload;
		int payloadlen;
		if(recv_rbudp_control_pkt(sockfd, buf, ether_size, &payload, &payloadlen, NULL, NULL)) {
			struct rbudp_initial_pkt parsed_pkt;
			if(rbudp_parse_initial(payload, payloadlen, &parsed_pkt)) {
				rx_state = make_rx_state(parsed_pkt.filesize, parsed_pkt.chunklen, sockfd);
				if(!rx_state)
					return false;

				rx_handle_initial(sockfd, &parsed_pkt, buf, payload, payloadlen);
				return true;
			}
		}
	}
}

static void rx_get_rtt_estimate(void *arg)
{
	int sockfd = (int) (u64) arg;
	char buf[ether_size];
	const char *payload;
	int payloadlen;
	const struct scionaddrhdr_ipv4 *scionaddrhdr;
	const struct udphdr *udphdr;
	if(recv_rbudp_control_pkt(sockfd, buf, ether_size, &payload, &payloadlen, &scionaddrhdr, &udphdr)) {
		u64 now = get_nsecs();
		rx_state->handshake_rtt = (now - rx_state->cts_sent_at) / 1000;
	} else {
		exit_with_error(ETIMEDOUT);
	}
}

static void configure_queues()
{
	ethtool_rules = calloc(num_local_addrs, sizeof(int));
	for(int l = 0; l < num_local_addrs; l++) {
		debug_printf("map UDP4 flow to %d.%d.%d.%d to queue %d",
					 (u8) (local_addrs[l].ip),
					 (u8) (local_addrs[l].ip >> 8u),
					 (u8) (local_addrs[l].ip >> 16u),
					 (u8) (local_addrs[l].ip >> 24u),
					 queues[l % num_queues]
		);

		char cmd[1024];
		int cmd_len = snprintf(cmd, 1024, "ethtool -N %s flow-type udp4 dst-ip %d.%d.%d.%d action %d",
							   opt_ifname,
							   (u8) (local_addrs[l].ip),
							   (u8) (local_addrs[l].ip >> 8u),
							   (u8) (local_addrs[l].ip >> 16u),
							   (u8) (local_addrs[l].ip >> 24u),
							   queues[l % num_queues]
		);
		if(cmd_len > 1023) {
			printf("could not configure queue %d - command too long, abort\n", queues[l % num_queues]);
		}

		FILE *proc = popen(cmd, "r");
		int rule_id;
		int num_parsed = fscanf(proc, "Added rule with ID %d", &rule_id);
		int ret = pclose(proc);
		if(ret != 0) {
			printf("could not configure queue %d, abort\n", queues[l % num_queues]);
			exit_with_error(ret);
		}
		if(num_parsed != 1) {
			printf("could not configure queue %d, abort\n", queues[l % num_queues]);
			exit_with_error(EXIT_FAILURE);
		}
		ethtool_rules[num_ethtool_rules] = rule_id;
		num_ethtool_rules++;
	}
}

static void unconfigure_queues() {
	for(int r = 0; r < num_ethtool_rules; r++) {
		char cmd[1024];
		int cmd_len = snprintf(cmd, 1024, "ethtool -N %s delete %d", opt_ifname, ethtool_rules[r]);
		if(cmd_len > 1023) { // This will never happen as the command to configure is strictly longer than this one
			printf("could not unconfigure rule %d - command too long, abort\n", r);
		}
		int ret = system(cmd);
		if (ret < 0) {
			exit_with_error(-ret);
		}
		if (ret > 0) {
			exit_with_error(ret);
		}
	}
}

static void rx_rtt_and_configure(void *arg)
{
	rx_get_rtt_estimate(arg);
	// as soon as we got the RTT estimate, we are ready to set up the queues
	configure_queues();
}

static void rx_send_cts_ack(int sockfd)
{
	struct hercules_path path;
	struct hercules_path_header path_header;
	if(!rx_get_reply_path(&path, &path_header)) {
		debug_printf("no reply path");
		return;
	}

	char buf[ether_size];
	void *rbudp_pkt = mempcpy(buf, path.headers[0].header, path.headerlen);

	struct hercules_control_packet control_pkt = {
			.type = CONTROL_PACKET_TYPE_ACK,
			.payload.ack.num_acks = 0,
	};

	fill_rbudp_pkt(rbudp_pkt, UINT_MAX, PCC_NO_PATH, 0, (char *) &control_pkt,
				sizeof(control_pkt.type) + ack__len(&control_pkt.payload.ack), path.payloadlen);
	stitch_checksum(&path, path.headers[0].checksum, buf);

	send_eth_frame(sockfd, buf, path.framelen);
	atomic_fetch_add(&tx_npkts, 1);
}

static void rx_send_acks(int sockfd)
{
	struct hercules_path path;
	struct hercules_path_header path_header;
	if(!rx_get_reply_path(&path, &path_header)) {
		debug_printf("no reply path");
		return;
	}

	char buf[ether_size];
	void *rbudp_pkt = mempcpy(buf, path.headers[0].header, path.headerlen);

	// XXX: could write ack payload directly to buf, but
	// doesnt work nicely with existing fill_rbudp_pkt helper.
	struct hercules_control_packet control_pkt = {
			.type = CONTROL_PACKET_TYPE_ACK,
	};

	const size_t max_entries = ack__max_num_entries(path.payloadlen - rbudp_headerlen - sizeof(control_pkt.type));
	for(u32 curr = 0; curr < rx_state->total_chunks;) {
		// Data to send
		curr = fill_ack_pkt(curr, &control_pkt.payload.ack, max_entries);
		if(control_pkt.payload.ack.num_acks == 0) break;

		fill_rbudp_pkt(rbudp_pkt, UINT_MAX, PCC_NO_PATH, 0, (char *) &control_pkt,
				 sizeof(control_pkt.type) + ack__len(&control_pkt.payload.ack), path.payloadlen);
		stitch_checksum(&path, path.headers[0].checksum, buf);

		send_eth_frame(sockfd, buf, path.framelen);
		atomic_fetch_add(&tx_npkts, 1);
	}
}

static void rx_trickle_acks(int sockfd)
{
	// XXX: data races in access to shared rx_state!
	while(!rx_received_all(rx_state)) {
		rx_send_acks(sockfd);
		sleep_nsecs(ACK_RATE_TIME_MS * 1e6);
	}
}

static void rx_send_path_nacks(int sockfd, struct receiver_state_per_path *path_state, u8 path_idx)
{
	struct hercules_path path;
	struct hercules_path_header path_header;
	if(!rx_get_reply_path(&path, &path_header)) {
		debug_printf("no reply path");
		return;
	}

	char buf[ether_size];
	void *rbudp_pkt = mempcpy(buf, path.headers[0].header, path.headerlen);

	// XXX: could write ack payload directly to buf, but
	// doesnt work nicely with existing fill_rbudp_pkt helper.
	struct hercules_control_packet control_pkt = {
			.type = CONTROL_PACKET_TYPE_NACK,
	};
	const size_t max_entries = ack__max_num_entries(path.payloadlen - rbudp_headerlen - sizeof(control_pkt.type));
	seqnr nack_end = path_state->prev_nack_end;
	for(u32 curr = path_state->prev_nack_end; curr < path_state->seq_rcvd.num;) {
		// Data to send
		curr = fill_nack_pkt(curr, &control_pkt.payload.ack, max_entries, &path_state->seq_rcvd);
		if(control_pkt.payload.ack.num_acks == 0) break;

		nack_end = control_pkt.payload.ack.acks[control_pkt.payload.ack.num_acks - 1].end;
		fill_rbudp_pkt(rbudp_pkt, UINT_MAX, path_idx, 0, (char *) &control_pkt,
					   sizeof(control_pkt.type) + ack__len(&control_pkt.payload.ack), path.payloadlen);
		stitch_checksum(&path, path.headers[0].checksum, buf);

		send_eth_frame(sockfd, buf, path.framelen);
		atomic_fetch_add(&tx_npkts, 1);
	}
	// we want to send each NACK range twice, so we store the ends of the two last batches sent
	path_state->prev_nack_end = path_state->nack_end;
	path_state->nack_end = nack_end;
}

// sends the NACKs used for congestion control by the sender
static void rx_send_nacks(int sockfd)
{
	u8 num_paths = atomic_load(&rx_state->num_tracked_paths);
	for(u8 p = 0; p < num_paths; p++) {
		rx_send_path_nacks(sockfd, &rx_state->path_state[p], p);
	}
}

static void rx_trickle_nacks(int sockfd)
{
	while(!rx_received_all(rx_state)) {
		u64 ack_round_start = get_nsecs();
		rx_send_nacks(sockfd);
		sleep_until(ack_round_start + rx_state->handshake_rtt * 1000 / 4);
	}
}

static void *rx_p(void *arg)
{
	while(running && !rx_received_all(rx_state)) {
		rx_receive_batch(arg);
	}

	return NULL;
}

// Helper function: open a AF_PACKET socket and bind it to the given interface.
// @returns -1 on error
static int socket_on_if(int ifindex)
{
	int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if(sockfd == -1) {
		return -1;
	}
	struct sockaddr_ll sockaddr;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sll_family = PF_PACKET;
	sockaddr.sll_protocol = htons(ETH_P_IP);
	sockaddr.sll_ifindex = ifindex;
	if(bind(sockfd, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) == -1) {
		return -1;
	}
	return sockfd;
}

static int load_bpf(const void *prgm, ssize_t prgm_size, struct bpf_object **obj)
{
	static const int log_buf_size = 16 * 1024;
	char log_buf[log_buf_size];
	int prog_fd;

	char tmp_file[] = "/tmp/hrcbpfXXXXXX";
	int fd = mkstemp(tmp_file);
	if(fd < 0) {
		return -errno;
	}
	if(prgm_size != write(fd, prgm, prgm_size)) {
		debug_printf("Could not write bpf file");
		return -EXIT_FAILURE;
	}

	struct bpf_object *_obj;
	if(obj == NULL) {
		obj = &_obj;
	}
	int ret = bpf_prog_load(tmp_file, BPF_PROG_TYPE_XDP, obj, &prog_fd);
	debug_printf("error loading file(%s): %d %s", tmp_file, -ret, strerror(-ret));
	int unlink_ret = unlink(tmp_file);
	if(0 != unlink_ret) {
		fprintf(stderr, "Could not remove temporary file, error: %d", unlink_ret);
	}
	if(ret != 0) {
		printf("BPF log buffer:\n%s", log_buf);
		return ret;
	}
	return prog_fd;
}

static void set_bpf_prgm_active(int prog_fd)
{
	int err = bpf_set_link_xdp_fd(opt_ifindex, prog_fd, opt_xdp_flags);
	if(err) {
		exit_with_error(-err);
	}

	int ret = bpf_get_link_xdp_id(opt_ifindex, &prog_id, opt_xdp_flags);
	if(ret) {
		exit_with_error(-ret);
	}
}

// XXX Workaround: the i40e driver (in zc mode) does not seem to allow sending if no program is loaded.
//	   Load an XDP program that just passes all packets (i.e. does the same thing as no program).
static int load_xsk_pass()
{
	int prog_fd;
	prog_fd = load_bpf(bpf_prgm_pass, bpf_prgm_pass_size, NULL);
	if(prog_fd < 0) {
		exit_with_error(-prog_fd);
	}

	set_bpf_prgm_active(prog_fd);
	return 0;
}

static void xsk_map__add_xsk(xskmap map, int index, struct xsk_socket_info *xsk)
{
	int xsk_fd = xsk_socket__fd(xsk->xsk);
	if(xsk_fd < 0) {
		exit_with_error(-xsk_fd);
	}
	bpf_map_update_elem(map, &index, &xsk_fd, 0);
}

/*
 * Load a BPF program redirecting IP traffic to the XSK.
 */
static void load_xsk_redirect_userspace(struct xsk_socket_info *xsks[])
{
	struct bpf_object *obj;
	int prog_fd = load_bpf(bpf_prgm_redirect_userspace, bpf_prgm_redirect_userspace_size, &obj);
	if(prog_fd < 0) {
		exit_with_error(prog_fd);
	}

	// push XSKs
	int xsks_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
	if(xsks_map_fd < 0) {
		debug_printf("Note that the BPF program assumes a maximum number of 256 queues on the NIC.");
		exit_with_error(-xsks_map_fd);
	}
	for(int q = 0; q < num_queues; q++) {
		xsk_map__add_xsk(xsks_map_fd, queues[q], xsks[q]);
	}

	// push local addresses
	int ips_fd = bpf_object__find_map_fd_by_name(obj, "local_addrs");
	if(ips_fd < 0) {
		exit_with_error(-ips_fd);
	}
	int ports_fd = bpf_object__find_map_fd_by_name(obj, "local_ports");
	if(ports_fd < 0) {
		exit_with_error(-ips_fd);
	}
	for(int a = 0; a < num_local_addrs; a++) {
		bpf_map_update_elem(ips_fd, &local_addrs[a].ip, &a, 0);
		bpf_map_update_elem(ports_fd, &a, &local_addrs[a].port, 0);
	}

	// push local_ia
	int ia_fd = bpf_object__find_map_fd_by_name(obj, "local_ia");
	if(ia_fd < 0) {
		exit_with_error(-ia_fd);
	}
	u32 key = 0;
	bpf_map_update_elem(ia_fd, &key, &local_ia, 0);
	set_bpf_prgm_active(prog_fd);
}

static void *tx_p(__attribute__ ((unused)) void *arg)
{
	load_xsk_pass();
	tx_only();

	return NULL;
}

void hercules_init(int ifindex, const ia local_ia_, const struct local_addr *local_addrs_, int num_local_addrs_,
				   int queues_[], int num_queues_, int mtu)
{
	if(HERCULES_MAX_HEADERLEN + sizeof(struct rbudp_initial_pkt) + rbudp_headerlen > (size_t)mtu) {
		printf("MTU too small (min: %lu, given: %d)",
			   HERCULES_MAX_HEADERLEN + sizeof(struct rbudp_initial_pkt) + rbudp_headerlen,
			   mtu
		);
		exit_with_error(EINVAL);
	}
	if(MAX_NUM_LOCAL_ADDRS <num_local_addrs_) {
		printf("Too many local addresses: %d provided, only up to %d supported", num_local_addrs_, MAX_NUM_LOCAL_ADDRS);
		exit_with_error(EINVAL);
	}

	ether_size = mtu;
	num_queues = num_queues_;
	queues = calloc(num_queues, sizeof(*queues));
	memcpy(queues, queues_, sizeof(*queues) * num_queues);
	static char if_name_buf[IF_NAMESIZE];
	opt_ifindex = ifindex;

	if_indextoname(ifindex, if_name_buf);
	int ifname_size = strlen(if_name_buf) + 1;
	opt_ifname = malloc(ifname_size);
	memcpy(opt_ifname, if_name_buf, ifname_size);

	local_ia = local_ia_;
	num_local_addrs = num_local_addrs_;
	local_addrs = calloc(num_local_addrs_, sizeof(*local_addrs));
	memcpy(local_addrs, local_addrs_, sizeof(*local_addrs) * num_local_addrs);

	debug_printf("ifindex: %i", opt_ifindex);
	for(int q = 0; q < num_queues; q++) {
		debug_printf("enabling queue %d", queues[q]);
	}

	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	setlocale(LC_ALL, "");
	if(setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
				strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static struct hercules_stats tx_stats(struct sender_state *t)
{
	u32 completed_chunks = 0;
	u64 rate_limit = 0;
	for(u32 r = 0; r < t->num_receivers; r++) {
		const struct sender_state_per_receiver *receiver = &t->receiver[r];
		completed_chunks += t->receiver[r].acked_chunks.num_set;
		for(u8 p = 0; p < receiver->num_paths; p++) {
			if(receiver->cc_states == NULL) { // no path-specific rate-limit
				rate_limit += t->rate_limit;
			} else { // PCC provided limit
				rate_limit += receiver->cc_states[p].curr_rate;
			}
		}
	}
	return (struct hercules_stats) {
			.start_time = t->start_time,
			.end_time = t->end_time,
			.now = get_nsecs(),
			.tx_npkts = tx_npkts,
			.rx_npkts = rx_npkts,
			.filesize = t->filesize,
			.framelen = ether_size,
			.chunklen = t->chunklen,
			.total_chunks = t->total_chunks * t->num_receivers,
			.completed_chunks = completed_chunks,
			.rate_limit = umin64(t->rate_limit, rate_limit),
	};
}

static struct hercules_stats rx_stats(struct receiver_state *r)
{
	return (struct hercules_stats) {
			.start_time = r->start_time,
			.end_time = r->end_time,
			.now = get_nsecs(),
			.tx_npkts = tx_npkts,
			.rx_npkts = rx_npkts,
			.filesize = r->filesize,
			.framelen = ether_size,
			.chunklen = r->chunklen,
			.total_chunks = r->total_chunks,
			.completed_chunks = r->received_chunks.num_set,
			.rate_limit = 0
	};
}

struct hercules_stats hercules_get_stats()
{
	if(!tx_state && !rx_state) {
		return (struct hercules_stats) {
				.start_time = 0
		};
	}

	if(tx_state) {
		return tx_stats(tx_state);
	} else {
		return rx_stats(rx_state);
	}
}


static pthread_t start_thread(void *(start_routine), void *arg)
{
	pthread_t pt;
	int ret = pthread_create(&pt, NULL, start_routine, arg);
	if(ret)
		exit_with_error(ret);
	return pt;
}

static void join_thread(pthread_t pt)
{
	int ret = pthread_join(pt, NULL);
	if(ret) {
		exit_with_error(ret);
	}
}

static void stop_thread(pthread_t pt)
{
	int ret = pthread_cancel(pt);
	if(ret) {
		exit_with_error(ret);
	}
}

struct hercules_stats
hercules_tx(const char *filename, const struct hercules_app_addr *destinations, struct hercules_path *paths_per_dest,
			int num_dests, const int *num_paths, int max_paths, int max_rate_limit, bool enable_pcc, int xdp_mode)
{
	// Open mmaped send file
	int f = open(filename, O_RDONLY);
	if(f == -1) {
		exit_with_error(errno);
	}

	struct stat stat;
	int ret = fstat(f, &stat);
	if(ret) {
		exit_with_error(errno);
	}
	const size_t filesize = stat.st_size;

	char *mem = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE | MAP_POPULATE, f, 0);
	if(mem == MAP_FAILED) {
		fprintf(stderr, "ERR: memory mapping failed\n");
		exit_with_error(errno);
	}
	close(f);

	// Open RAW socket for control messages
	int sockfd = socket_on_if(opt_ifindex);
	if(sockfd == -1) {
		exit_with_error(errno);
	}

	u32 chunklen = paths_per_dest[0].payloadlen - rbudp_headerlen;
	for(int d = 0; d < num_dests; d++) {
		for(int p = 0; p < num_paths[d]; p++) {
			chunklen = umin32(chunklen, paths_per_dest[d * max_paths + p].payloadlen - rbudp_headerlen);
		}
	}
	init_tx_state(filesize, chunklen, max_rate_limit, mem, destinations, paths_per_dest, num_dests, num_paths, max_paths, sockfd);

	if(!tx_handshake(sockfd)) {
		exit_with_error(ETIMEDOUT);
	}

	if(enable_pcc) {
		u64 now = get_nsecs();
		for(int d = 0; d < num_dests; d++) {
			struct sender_state_per_receiver *receiver = &tx_state->receiver[d];
			receiver->cc_states = init_ccontrol_state(
					max_rate_limit,
					tx_state->total_chunks,
					*num_paths,
					max_paths,
					max_paths * num_dests
			);
			ccontrol_update_rtt(&receiver->cc_states[0], receiver->handshake_rtt);
			debug_printf("[receiver %d] [path 0] handshake_rtt: %fs, MI: %fs",
						 d, receiver->handshake_rtt / 1e9, receiver->cc_states[0].pcc_mi_duration);

			// make sure tx_only() performs RTT estimation on every enabled path
			for(u32 p = 1; p < receiver->num_paths; p++) {
				receiver->paths[p].next_handshake_at = now;
			}
		}
	}

	tx_state->rate_limit = max_rate_limit;

	// Wait for CTS from receiver
	printf("Waiting for receiver to get ready..."); fflush(stdout);
	if(!tx_await_cts(sockfd)) {
		exit_with_error(ETIMEDOUT);
	}
	printf(" OK\n");

	init_send_queue(&send_queue, BATCH_SIZE);

	pthread_t senders[num_queues];
	struct xsk_socket_info *xsks[num_queues];
	for(int q = 0; q < num_queues; q++) {
		xsks[q] = create_xsk_with_umem(XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, queues[q], xdp_mode);
		senders[q] = start_thread(tx_send_p, xsks[q]);
		submit_initial_rx_frames(xsks[q]->umem);
	}

	tx_state->start_time = get_nsecs();
	running = true;
	pthread_t worker = start_thread(tx_p, NULL);

	tx_recv_control_messages(sockfd);

	tx_state->end_time = get_nsecs();
	running = false;
	join_thread(worker);

	for(int q = 0; q < num_queues; q++) {
		stop_thread(senders[q]);
		close_xsk(xsks[q]);
	}
	destroy_send_queue(&send_queue);

	struct hercules_stats stats = tx_stats(tx_state);

	if(enable_pcc) {
		for(int d = 0; d < num_dests; d++) {
			destroy_ccontrol_state(tx_state->receiver[d].cc_states, num_paths[d]);
		}
	}
	destroy_tx_state();
	close(sockfd);

	return stats;
}

struct hercules_stats hercules_rx(const char *filename, int xdp_mode, bool configure_queues)
{
	// Open RAW socket to receive and send control messages on
	// Note: this socket will not receive any packets once the XSK has been
	//			 opened, which will then receive packets in the main RX thread.
	int sockfd = socket_on_if(opt_ifindex);
	if(sockfd == -1) {
		exit_with_error(errno);
	}

	if(!rx_accept(sockfd)) {
		exit_with_error(EBADMSG);
	}
	pthread_t rtt_estimator;
	if(configure_queues) {
		rtt_estimator = start_thread(rx_rtt_and_configure, (void *)(u64)sockfd);
	} else {
		rtt_estimator = start_thread(rx_get_rtt_estimate, (void *)(u64)sockfd);
	}
	debug_printf("Filesize %lu Bytes, %u total chunks of size %u.",
				 rx_state->filesize, rx_state->total_chunks, rx_state->chunklen);
	printf("Preparing file for receive..."); fflush(stdout);
	rx_state->mem = rx_mmap(filename, rx_state->filesize);
	printf(" OK\n");
	join_thread(rtt_estimator);
	debug_printf("cts_rtt: %fs", rx_state->handshake_rtt / 1e6);

	struct xsk_socket_info *xsks[num_queues];
	for(int q = 0; q < num_queues; q++) {
		struct xsk_socket_info *xsk = create_xsk_with_umem(XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, queues[q], xdp_mode);
		xsks[q] = xsk;
		submit_initial_rx_frames(xsk->umem);
	}

	load_xsk_redirect_userspace(xsks);

	rx_state->start_time = get_nsecs();
	running = true;

	pthread_t worker[num_queues];
	for(int q = 0; q < num_queues; q++) {
		worker[q] = start_thread(rx_p, xsks[q]);
	}

	rx_send_cts_ack(sockfd); // send Clear To Send ACK
	pthread_t trickle_pcc = start_thread(rx_trickle_nacks, (void *) (u64) sockfd);
	rx_trickle_acks(sockfd);
	rx_send_acks(sockfd);

	rx_state->end_time = get_nsecs();
	running = false;

	join_thread(trickle_pcc);
	for(int q = 0; q < num_queues; q++) {
		join_thread(worker[q]);
	}

	struct hercules_stats stats = rx_stats(rx_state);

	unconfigure_queues();
	for(int q = 0; q < num_queues; q++) {
		close_xsk(xsks[q]);
	}
	bitset__destroy(&rx_state->received_chunks);
	free(rx_state);
	close(sockfd);
	return stats;
}

void hercules_close()
{
	// Only essential cleanup.
	remove_xdp_program();
	unconfigure_queues();
}
