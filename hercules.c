// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2017 - 2018 Intel Corporation.
// Copyright(c) 2019 ETH Zurich.

// Enable extra warnings; cannot be enabled in CFLAGS because cgo generates a
// ton of warnings that can apparantly not be suppressed.
#pragma GCC diagnostic warning "-Wextra"

#include "hercules.h"
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

#include "bpf/libbpf.h"
#include "bpf/bpf.h"
#include "bpf/xsk.h"
#include "linux/filter.h" // actually linux/tools/include/linux/filter.h

#include "bitset.h"
#include "libscion_checksum.h"
#include "congestion_control.h"
#include "utils.h"


#ifndef NDEBUG
#define debug_printf(fmt, ...) printf("DEBUG: %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define debug_printf(...) ;
#endif

#define SCION_ENDHOST_PORT 30041 // aka SCION_UDP_EH_DATA_PORT

#define L4_SCMP 1
// #define L4_UDP 17 //  == IPPROTO_UDP


#define NUM_FRAMES (4 * 1024)
#define BATCH_SIZE 64


#define ETHER_SIZE 1500
#define RATE_LIMIT_CHECK 1000 // check rate limit every X packets
						// Maximum burst above target pps allowed

#define ACK_RATE_TIME_MS 100 // send ACKS after at most X milliseconds

static const int rbudp_headerlen = 4;
static const int tx_handshake_retries = 5;


// exported from hercules.go
extern int HerculesGetReplyPath(const char *packetPtr, int length, struct hercules_path *reply_path);


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

// Structure of first RBUDP packet sent by sender.
// Integers all transmitted in little endian (host endianness).
struct rbudp_initial_pkt
{
	u64 filesize;
	u32 chunklen;
	unsigned long timestamp;
};

// Structure of ACK RBUDP packets sent by the receiver.
// Integers all transmitted in little endian (host endianness).
struct rbudp_ack_pkt
{
	u8 num_acks; //!< number of (valid) entries in `acks`
	struct {
		u32 begin; //!< index of first chunk that is ACKed with this range
		u32 end;   //!< one-past-the-last chunk that is ACKed with this range
	} acks[256]; //!< list of ranges that are ACKed
};
#pragma pack(pop)

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

struct receiver_state {
	/** Filesize in bytes */
	size_t filesize;
	/** Size of file data (in byte) per packet */
	u32 chunklen;
	/** Number of packets that will make up the entire file. Equal to `ceil(filesize/chunklen)` */
	u32 total_chunks;
	/** Memory mapped file for receive */
	char *mem;

	struct bitset received_chunks;

	// XXX: reads/writes to this is are a huge data race. Need to sync.
	char rx_sample_buf[XSK_UMEM__DEFAULT_FRAME_SIZE];
	int rx_sample_len;

	// Start/end time of the current transfer
	u64 start_time;
	u64 end_time;
};

struct sender_state_per_receiver {
	/** Map chunk_id to path_id */
	u32 *path_map;
	/** Next batch should be sent via this path */
	u32 path_index;

	struct bitset acked_chunks;
	u64 handshake_rtt; // Handshake RTT in ns

	u32 num_paths;
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

	_Atomic u32 rate_limit;

	// Start/end time of the current transfer
	u64 start_time;
	u64 end_time;

	u32 num_receivers;
	struct sender_state_per_receiver *receiver;
};

// XXX: cleanup naming: these things are called `opt_XXX` because they corresponded to options in the example application.
static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static const char *opt_ifname = "";
static int opt_ifindex;
static int opt_queue;
static struct hercules_app_addr local_addr; // XXX: this shouldn't need to be global.

static u32 prog_id;

static struct receiver_state *rx_state;
static struct sender_state *tx_state;

// State for transmit rate control
static size_t tx_npkts;
static size_t prev_rate_check;
static size_t prev_tx_npkts;
// State for receive rate, for stat dump only
static size_t rx_npkts;

static bool running;


/**
 * @param scionaddrhdr
 * @return The receiver index given by the sender address in scionaddrhdr
 */
static u32 rcvr_by_src_address(const struct scionaddrhdr_ipv4 *scionaddrhdr, const struct udphdr *udphdr)
{
	u32 r;
	for (r = 0; r < tx_state->num_receivers; r++) {
		struct hercules_app_addr *addr = &tx_state->receiver[r].addr;
		if (scionaddrhdr->src_ia == addr->ia && scionaddrhdr->src_ip == addr->ip && udphdr->uh_sport == addr->port) {
			break;
		}
	}
	return r;
}

static void fill_rbudp_pkt(void *rbudp_pkt, u32 chunk_idx, const char *data, size_t n, size_t payloadlen);
static bool rbudp_parse_initial(const char *pkt, size_t len, struct rbudp_initial_pkt *parsed_pkt);
static void stitch_checksum(const struct hercules_path *path, char *pkt);

static bool rx_received_all(const struct receiver_state *r) {
	return (r->received_chunks.num_set == r->total_chunks);
}

static bool tx_acked_all(const struct sender_state *t) {
	for (u32 r = 0; r < tx_state->num_receivers; r++) {
		if(t->receiver[r].acked_chunks.num_set != t->total_chunks) {
			return false;
		}
	}
	return true;
}

static void set_rx_sample(struct receiver_state* r, const char *pkt, int len)
{
	r->rx_sample_len = len;
	memcpy(r->rx_sample_buf, pkt, len);
}

static void remove_xdp_program(void)
{
	u32 curr_prog_id = 0;

	if (bpf_get_link_xdp_id(opt_ifindex, &curr_prog_id, opt_xdp_flags)) {
		printf("bpf_get_link_xdp_id failed\n");
		exit(EXIT_FAILURE);
	}
	if (prog_id == curr_prog_id)
		bpf_set_link_xdp_fd(opt_ifindex, -1, opt_xdp_flags);
	else if (!curr_prog_id)
		printf("couldn't find a prog id on a given interface\n");
	else
		printf("program on interface changed, not removing\n");
}

static void __exit_with_error(int error, const char *file, const char *func, int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func, line, error, strerror(error));
	remove_xdp_program();
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
	if (!input) {
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
	l4_type = htons((u16)IPPROTO_UDP);
	const struct scionhdr *scionh = (const struct scionhdr *) ptr;
	udp_hdr = ptr + scionh->header_len * 8;
	// L4 protocol type
	chk_add_chunk(input, (u8*)&l4_type, 2);
	// udp src+dst port and len fields.
	ptr = chk_add_chunk(input, udp_hdr, 6);
	// Use blank checksum field
	chk_add_chunk(input, (u8 *)(&blank_sum), 2);
	ptr += 2; // Skip over packet checksum
	// Length in UDP header includes header size, so subtract it.
	payload_len = ntohs(*(u16 *)(udp_hdr + 4)) - 8;
	if (payload_len != len - 8) {
		debug_printf("Invalid payload_len: Got %u, Expected: %d", payload_len, len - 8);
		return 0;
	}
	chk_add_chunk(input, ptr, payload_len);

	u16 computed_checksum = checksum(input);
	return computed_checksum;
}

// Parse ethernet/IP/UDP/SCION/UDP packet,
// check that it is addressed to us,
// check SCION-UDP checksum if set.
// sets scionaddrh_o to SCION address header, if provided
// return rbudp-packet (i.e. SCION/UDP packet payload)
static const char* parse_pkt(const char *pkt, size_t length, bool check, const struct scionaddrhdr_ipv4 **scionaddrh_o, const struct udphdr **udphdr_o)
{
	// Parse Ethernet frame
	if(sizeof(struct ether_header) > length) {
		debug_printf("too short for eth header: %zu", length);
		return NULL;
	}
	const struct ether_header *eh = (const struct ether_header *)pkt;
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
		//debug_printf("not UDP: %u, %zu", iph->protocol, offset);
		return NULL;
	}
	if(iph->daddr != local_addr.ip) {
		debug_printf("not addressed to us (IP overlay)");
		return NULL;
	}
	offset += iph->ihl * 4; // IHL is header length, in number of 32-bit words.

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
								 ntohs(scionh->ver_dst_src) >> 6  & 0x3f,
								 ntohs(scionh->ver_dst_src) >> 0  & 0x3f);
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
	const struct scionaddrhdr_ipv4 *scionaddrh = (const struct scionaddrhdr_ipv4 *) (pkt + offset + 8);
	if(scionaddrh->dst_ia != local_addr.ia) {
		debug_printf("not addressed to us (IA)");
		return NULL;
	}
	if(scionaddrh->dst_ip != local_addr.ip) {
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
	if(l4udph->dest != local_addr.port) {
		debug_printf("not addressed to us (L4 UDP port): %u", ntohs(l4udph->dest));
		return NULL;
	}

	if(check) {
		u16 header_checksum = l4udph->check;
		u16 computed_checksum = scion_udp_checksum((u8 *)scionh, length - offset);
		if (header_checksum != computed_checksum) {
			debug_printf("Checksum in SCION/UDP header %u "
					"does not match computed checksum %u",
					ntohs(header_checksum), ntohs(computed_checksum));
			return NULL;
		}
	}

	offset += sizeof(struct udphdr);
	if(scionaddrh_o != NULL) {
		*scionaddrh_o = scionaddrh;
	}
	if(udphdr_o != NULL) {
		*udphdr_o = l4udph;
	}
	return pkt + offset;
}

static bool recv_rbudp_control_pkt(int sockfd, char *buf, size_t buflen, const char **payload, int *payloadlen, const struct scionaddrhdr_ipv4 **scionaddrh, const struct udphdr **udphdr)
{
	ssize_t len = recv(sockfd, buf, buflen, 0); // XXX set timeout
	if(len == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			return false;
		}
		exit_with_error(errno); // XXX: are there situations where we want to try again?
	}

	const char *rbudp_pkt = parse_pkt(buf, len, true, scionaddrh, udphdr);
	if(rbudp_pkt == NULL) {
		return false;
	}

	const size_t rbudp_len = len - (rbudp_pkt-buf);
	if(rbudp_len < sizeof(u32)) {
		return false;
	}
	u32 chunk_idx;
	memcpy(&chunk_idx, rbudp_pkt, sizeof(u32));
	if(chunk_idx != UINT_MAX) {
		return false;
	}

	rx_npkts++;

	*payload = rbudp_pkt + rbudp_headerlen;
	*payloadlen = rbudp_len - rbudp_headerlen;
	return true;
}

static bool handle_rbudp_data_pkt(const char *pkt, size_t length)
{
	if (length < rbudp_headerlen + rx_state->chunklen) {
		return false;
	}

	u32 chunk_idx;
	memcpy(&chunk_idx, pkt, sizeof(u32));
	if (chunk_idx >= rx_state->total_chunks) {
		if(chunk_idx == UINT_MAX) {
			fprintf(stderr, "ERROR: expected RBUDP data packet, got RBUDP control packet. Ignoring it.\n");
		} else {
			fprintf(stderr, "ERROR: chunk_idx larger than expected: %u >= %u\n",
					chunk_idx, rx_state->total_chunks);
		}
		return false;
	}
	// mark as received in received_chunks bitmap
	bool prev = bitset__set(&rx_state->received_chunks, chunk_idx);
	if(!prev) {
		const char *payload = pkt + rbudp_headerlen;
		const size_t chunk_start = (size_t)chunk_idx * rx_state->chunklen;
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
	if (!umem)
		exit_with_error(errno);

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
						 NULL);
	if (ret)
		exit_with_error(-ret);

	umem->buffer = buffer;
	return umem;
}

static void submit_initial_rx_frames(struct xsk_socket_info *xsk)
{
	int initial_kernel_rx_frame_count = XSK_RING_PROD__DEFAULT_NUM_DESCS - BATCH_SIZE;
	u32 idx;
	int ret = xsk_ring_prod__reserve(&xsk->umem->fq,
						 initial_kernel_rx_frame_count,
						 &idx);
	if (ret != initial_kernel_rx_frame_count)
		exit_with_error(-ret);
	for (int i = 0; i < initial_kernel_rx_frame_count; i++)
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) = i * XSK_UMEM__DEFAULT_FRAME_SIZE;
	xsk_ring_prod__submit(&xsk->umem->fq, initial_kernel_rx_frame_count);
}

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem, int libbpf_flags, int bind_flags)
{
	struct xsk_socket_config cfg;
	struct xsk_socket_info *xsk;
	int ret;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		exit_with_error(errno);

	xsk->umem = umem;
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg.libbpf_flags = libbpf_flags;
	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = bind_flags;
	ret = xsk_socket__create(&xsk->xsk, opt_ifname, opt_queue, umem->umem,
				 &xsk->rx, &xsk->tx, &cfg);
	if (ret)
		exit_with_error(-ret);

	ret = bpf_get_link_xdp_id(opt_ifindex, &prog_id, opt_xdp_flags);
	if (ret)
		exit_with_error(-ret);

	return xsk;
}

// Helper function: create XSK with it's own UMEM
// Note: XSKs can share UMEM and this is the setup in the sample application.
// However, we don't care about this, and create a separate UMEM for each
// socket.
static struct xsk_socket_info* create_xsk_with_umem(int libbpf_flags, int bind_flags)
{
	void *bufs;
	int ret = posix_memalign(&bufs, getpagesize(), /* PAGE_SIZE aligned */
					 NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
	if (ret)
		exit_with_error(ret);

	struct xsk_umem_info *umem;
	umem = xsk_configure_umem(bufs, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
	return xsk_configure_socket(umem, libbpf_flags, bind_flags);
}

static void kick_tx(struct xsk_socket_info *xsk)
{
	int ret;
	do {
		ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	} while(ret < 0 && errno == EAGAIN);

	if (ret < 0 && errno != ENOBUFS && errno != EBUSY) {
		exit_with_error(errno);
	}
}

// Pop entries from completion ring.
// XXX: Here we SHOULD be updating the bookeeping for which frames are safe to be used for sending.
//      But we currently don't so the only thing this does is freeng up the completion ring.
static void pop_completion_ring(struct xsk_socket_info *xsk)
{
	if (!xsk->outstanding_tx)
		return;

	u32 idx;
	size_t entries = xsk_ring_cons__peek(&xsk->umem->cq, SIZE_MAX, &idx);
	if (likely(entries > 0)) {
		xsk_ring_cons__release(&xsk->umem->cq, entries);
		xsk->outstanding_tx -= entries;
		tx_npkts += entries;
	}
}

static u32 ack__max_num_entries(u32 len)
{
	struct rbudp_ack_pkt ack; // dummy declval
	return (len - sizeof(ack.num_acks)) / sizeof(ack.acks[0]);
}

static u32 ack__len(const struct rbudp_ack_pkt *ack)
{
	return sizeof(ack->num_acks) + ack->num_acks * sizeof(ack->acks[0]);
}

static u32 fill_ack_pkt(u32 first, struct rbudp_ack_pkt *ack, size_t max_num_acks)
{
	size_t e = 0;
	u32 curr = first;
	for(; e < max_num_acks;)
	{
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

static void send_eth_frame(int sockfd, void *buf, size_t len)
{
	struct sockaddr_ll addr;
	// Index of the network device
	addr.sll_ifindex = opt_ifindex;
	// Address length
	addr.sll_halen = ETH_ALEN;
	// Destination MAC; extracted from ethernet header
	memcpy(addr.sll_addr, buf, ETH_ALEN);

	ssize_t ret = sendto(sockfd, buf, len, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll));
	if(ret == -1) {
		exit_with_error(errno);
	}
}

static void tx_register_acks(const struct rbudp_ack_pkt *ack, u32 rcvr)
{
	for(uint16_t e = 0; e < ack->num_acks; ++e)
	{
		const u32 begin = ack->acks[e].begin;
		const u32 end   = ack->acks[e].end;
		if(begin >= end || end > tx_state->total_chunks) {
			return; // Abort
		}
		for(u32 i = begin; i < end; ++i) { // XXX: this can *obviously* be optimized
			bitset__set(&tx_state->receiver[rcvr].acked_chunks, i);
		}
		if (tx_state->receiver[rcvr].cc_states) {
			// Counts ACKed packets from the range that was sent during the MI.
			// ack_start is the packet with the lowest index sent during the MI,
			// ack_end the packet with the highest index that could have been sent during the MI
			// TODO: Improve the granularity of the accounting of the ACKed packets during a MI
			// if required by the CC algorithm.
			for(u32 i = begin; i < end; ++i) {
				bitset__set(&tx_state->receiver[rcvr].cc_states[tx_state->receiver[rcvr].path_map[i]].mi_acked_chunks, i);
			}
		}
	}
}

static bool pcc_mi_elapsed(const struct ccontrol_state *cc_state)
{
	unsigned long now = get_nsecs();
	unsigned long dt = now - cc_state->mi_start;
	return dt > (cc_state->pcc_mi_duration + cc_state->rtt) * 1e9;
}

static void pcc_monitor()
{
	for (u32 r = 0; r < tx_state->num_receivers; r++) {
		for (u32 cur_path = 0; cur_path < tx_state->receiver[r].num_paths; cur_path++) {
			struct ccontrol_state *cc_state = &tx_state->receiver[r].cc_states[cur_path];
			if (pcc_mi_elapsed(cc_state)) {
				u32 sent_mi = cc_state->mi_tx_npkts; // pkts sent in MI
				u32 acked_mi = cc_state->mi_acked_chunks.num_set; // acked pkts from MI

				sent_mi = umax32(sent_mi, 1);
				acked_mi = umin32(acked_mi, sent_mi);
				float loss = (sent_mi - acked_mi) / sent_mi;
				float throughput = cc_state->curr_rate * (1 - loss);

				u32 new_rate = pcc_control(cc_state, throughput, loss);

				bool retransmitting = tx_npkts > tx_state->total_chunks;
				// Reset MI state info, only safe because no acks are processed during those updates
				bitset__reset(&cc_state->mi_acked_chunks);
				if (!retransmitting) {
					cc_state->ack_start = tx_npkts;
					cc_state->ack_end = cc_state->ack_start + new_rate *
															  cc_state->pcc_mi_duration; // misses acks from a MI straddling initial transmissions and retransmission (efficiency trade-off)
				} else {
					// overestimates the number of pkts sent during MI (cc_state->mi_start not yet updated)
					cc_state->ack_start = bitset__scan_neg(&tx_state->receiver[r].acked_chunks, 0);
					// underestimates the number of pkts sent during MI (does not wrap)
					cc_state->ack_end = bitset__scan_neg_n(&tx_state->receiver[r].acked_chunks,
														   cc_state->ack_start,
														   new_rate * cc_state->pcc_mi_duration);
				}

				cc_state->mi_start = get_nsecs(); // start new MI
				cc_state->mi_tx_npkts = 0;
			}
		}
	}
}

static void tx_recv_acks(int sockfd)
{
	struct timeval to = { .tv_sec = 0, .tv_usec = 100 };
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

	char buf[ETHER_SIZE];
	while (!tx_acked_all(tx_state)) {
		const char *payload;
		int payloadlen;
		const struct scionaddrhdr_ipv4 *scionaddrhdr;
		const struct udphdr *udphdr;
		if(recv_rbudp_control_pkt(sockfd, buf, ETHER_SIZE, &payload, &payloadlen, &scionaddrhdr, &udphdr)) {
			const struct rbudp_ack_pkt *ack = (const struct rbudp_ack_pkt*)payload;
			if((u32)payloadlen >= ack__len(ack)) {
                tx_register_acks(ack, rcvr_by_src_address(scionaddrhdr, udphdr));
			}
		}

		if(tx_state->receiver[0].cc_states) {
            pcc_monitor();
		}
	}
}

static bool tx_handle_cts(const char *cts, u32 rcvr) {
	const struct rbudp_ack_pkt *ack = (const struct rbudp_ack_pkt *) cts;
	if (ack->num_acks == 0) {
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
		if (tx_state->receiver[r].cts_received) {
			received++;
		}
	}

	// Set 20 second timeout on the socket, wait for receiver to get ready
	struct timeval to = { .tv_sec = 20, .tv_usec = 0 };
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

	char buf[ETHER_SIZE];
	const char *payload;
	int payloadlen;
	const struct scionaddrhdr_ipv4 *scionaddrhdr;
	const struct udphdr *udphdr;
	for(u32 i = 0; i < tx_state->num_receivers; ++i) {
		if(recv_rbudp_control_pkt(sockfd, buf, ETHER_SIZE, &payload, &payloadlen, &scionaddrhdr, &udphdr)) {
			if (tx_handle_cts(payload, rcvr_by_src_address(scionaddrhdr, udphdr))) {
				received++;
				if (received >= tx_state->num_receivers) {
					return true;
				}
			}
		}
	}
	return false;
}

static bool tx_await_rtt_ack(int sockfd, const struct scionaddrhdr_ipv4 **scionaddrhdr, const struct udphdr **udphdr)
{
	const struct scionaddrhdr_ipv4 *scionaddrhdr_fallback;
	if (scionaddrhdr == NULL) {
		scionaddrhdr = &scionaddrhdr_fallback;
	}

	const struct udphdr *udphdr_fallback;
	if (udphdr == NULL) {
		udphdr = &udphdr_fallback;
	}

	// Set 1 second timeout on the socket
	struct timeval to = { .tv_sec = 1, .tv_usec = 0 };
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

	char buf[ETHER_SIZE];
	const char *payload;
	int payloadlen;
	if(recv_rbudp_control_pkt(sockfd, buf, ETHER_SIZE, &payload, &payloadlen, scionaddrhdr, udphdr)) {
		struct rbudp_initial_pkt parsed_pkt;
		if(rbudp_parse_initial(payload, payloadlen, &parsed_pkt)) {
			u32 rcvr = rcvr_by_src_address(*scionaddrhdr, *udphdr);
			if (rcvr < tx_state->num_receivers && tx_state->receiver[rcvr].handshake_rtt == 0) {
				tx_state->receiver[rcvr].handshake_rtt = (u64) (get_nsecs() - parsed_pkt.timestamp);
				if (parsed_pkt.filesize != tx_state->filesize ||
					parsed_pkt.chunklen != tx_state->chunklen) {
					debug_printf("Receiver disagrees "
								 "on transfer parameters:\n"
								 "filesize: %llu\nchunklen: %u",
								 parsed_pkt.filesize,
								 parsed_pkt.chunklen);
					return false;
				}
			} else {
				tx_handle_cts(payload, rcvr);
			}
			return true;
		}
	}
	return false;
}

static void tx_send_initial(int sockfd, const struct hercules_path *path, size_t filesize, u32 chunklen, unsigned long timestamp)
{
	char buf[ETHER_SIZE];
	void *rbudp_pkt = mempcpy(buf, path->header, path->headerlen);

	struct rbudp_initial_pkt pld = { .filesize = filesize, .chunklen = chunklen, .timestamp =  timestamp};
	fill_rbudp_pkt(rbudp_pkt, UINT_MAX, (char*)&pld, sizeof(pld), path->payloadlen);
	stitch_checksum(path, buf);

	send_eth_frame(sockfd, buf, path->framelen);
}

static bool tx_handshake(int sockfd)
{
	bool succeeded[tx_state->num_receivers];
	memset(succeeded, 0, sizeof(succeeded));
	for(int i = 0; i < tx_handshake_retries; ++i) {
		int await = 0;
		for (u32 r = 0; r < tx_state->num_receivers; r++) {
			if (!succeeded[r]) {
				unsigned long timestamp = get_nsecs();
				tx_send_initial(sockfd, &tx_state->receiver[r].paths[0], tx_state->filesize, tx_state->chunklen, timestamp);
				await++;
			}
		}

		const struct scionaddrhdr_ipv4 *scionaddrhdr;
		const struct udphdr *udphdr;
		while(tx_await_rtt_ack(sockfd, &scionaddrhdr, &udphdr)) {
			u32 rcvr = rcvr_by_src_address(scionaddrhdr, udphdr);
			if (rcvr < tx_state->num_receivers && !succeeded[rcvr]) {
				succeeded[rcvr] = true;
				await--;
				if (await == 0) {
					return true;
				}
			}
		}
		debug_printf("Timeout, retry.");
	}
	fprintf(stderr, "ERR: timeout during handshake. Gave up after %i tries.\n", tx_handshake_retries);
	return false;
}

static void stitch_checksum(const struct hercules_path *path, char *pkt)
{
	chk_input chk_input_s;
	chk_input *chksum_struc = init_chk_input(&chk_input_s, 2);
	assert(chksum_struc);
	char *payload = pkt + path->headerlen;
	u16 precomputed_checksum = ~path->checksum; // take one complement of precomputed checksum
	chk_add_chunk(chksum_struc,  (u8 *)&precomputed_checksum, 2); // add precomputed header checksum
	chk_add_chunk(chksum_struc, (u8 *)payload, path->payloadlen); // add payload
	u16 pkt_checksum = checksum(chksum_struc);

	mempcpy(payload - 2, &pkt_checksum, sizeof(pkt_checksum));
}

static void rx_receive_batch(struct xsk_socket_info *xsk)
{
	u32 idx_rx = 0, idx_fq = 0;
	int ignored = 0;

	// XXX: restricting to receiving BATCH_SIZE here seems unnecessary. Change to SIZE_MAX?
	size_t rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	size_t reserved = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	while (reserved != rcvd) {
		reserved = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
		if (!running)
			return;
	}

	for (size_t i = 0; i < rcvd; i++) {
		u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->addr;
		u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->len;
		const char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
		const char *rbudp_pkt = parse_pkt(pkt, len, true, NULL, NULL);
		if(rbudp_pkt &&
				handle_rbudp_data_pkt(rbudp_pkt, len - (rbudp_pkt-pkt)))
		{
			if(i == 0) { // XXX: race. too frequent
				set_rx_sample(rx_state, pkt, len);
			}
		} else {
			ignored++;
		}
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = addr;
	}
	xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
	xsk_ring_cons__release(&xsk->rx, rcvd);
	rx_npkts += (rcvd - ignored);
}

static void rate_limit_tx(void)
{
	if (prev_tx_npkts + RATE_LIMIT_CHECK > tx_npkts)
		return;

	u64 now = get_nsecs();
	u64 dt = now - prev_rate_check;

	u64 d_npkts = tx_npkts - prev_tx_npkts;

	dt = umin64(dt, 1);
	u32 tx_pps = d_npkts * 1000000000. / dt;

	if (tx_pps > tx_state->rate_limit) {
		u64 min_dt = (d_npkts * 1000000000. / tx_state->rate_limit);

		// Busy wait implementation
		while (now < prev_rate_check + min_dt) {
			now = get_nsecs();
		}
	}

	prev_rate_check = now;
	prev_tx_npkts = tx_npkts;
}

static u32 path_can_send_npkts(struct ccontrol_state *cc_state)
{
	u64 now = get_nsecs();
	u64 dt = now - cc_state->mi_start;

	dt = umin64(dt, 1);
	u32 tx_pps = cc_state->mi_tx_npkts * 1000000000. / dt;

	if (tx_pps > cc_state->curr_rate) {
		return 0;
	}
	return cc_state->curr_rate - tx_pps;
}

// Fill packet with n bytes from data and pad with zeros to payloadlen.
static void fill_rbudp_pkt(void *rbudp_pkt, u32 chunk_idx, const char *data, size_t n, size_t payloadlen)
{
	void *rbudp_payload = mempcpy(rbudp_pkt, &chunk_idx, sizeof(chunk_idx));
	void *start_pad = mempcpy(rbudp_payload, data, n);
	if(sizeof(chunk_idx) + n < payloadlen) {
		memset(start_pad, 0, payloadlen - sizeof(chunk_idx) - n);
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
static char* produce_frame(struct xsk_socket_info *xsk, u32 frame_nb, u32 prod_tx_idx, size_t framelen)
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
	if (*frame_nb + BATCH_SIZE > NUM_FRAMES) { // Wrap around if next batch would overflow
		*frame_nb = 0;
	}

	kick_tx(xsk);
	pop_completion_ring(xsk);
}

static void send_batch(struct xsk_socket_info *xsk, u32 *frame_nb, const struct hercules_path *path_by_rcvr[], const u32 chunks[], const u32 rcvr_by_chunk[], u32 num_chunks)
{
	// reserve TX producer ring
	u32 idx;
	while(xsk_ring_prod__reserve(&xsk->tx, num_chunks, &idx) != num_chunks)
	{
		kick_tx(xsk); // XXX: investigate how sender can still starve without this, it seems it should NOT be necessary
		// While we're waiting, consume completion ring to avoid that the kernel
		// could starve on completion ring slots. (ring is smaller than number of
		// frames)
		pop_completion_ring(xsk);
	}

	u32 chk;
	for (chk = 0; chk < num_chunks; ++chk)
	{
		void *pkt = produce_frame(xsk, *frame_nb + chk, idx + chk, path_by_rcvr[rcvr_by_chunk[chk]]->framelen);

		const u32 chunk_idx = chunks[chk];
		const size_t chunk_start = (size_t)chunk_idx * tx_state->chunklen;
		const size_t len = umin64(tx_state->chunklen, tx_state->filesize - chunk_start);

		void *rbudp_pkt = mempcpy(pkt, path_by_rcvr[rcvr_by_chunk[chk]]->header, path_by_rcvr[rcvr_by_chunk[chk]]->headerlen);
		fill_rbudp_pkt(rbudp_pkt, chunk_idx, tx_state->mem + chunk_start, len, path_by_rcvr[rcvr_by_chunk[chk]]->payloadlen);
		stitch_checksum(path_by_rcvr[rcvr_by_chunk[chk]], pkt);
	}
	submit_batch(xsk, frame_nb, chk);
}

// Collect path rate limits
u32 compute_max_chunks_per_rcvr(u32 *max_chunks_per_rcvr)
{
	u32 total_chunks = 0;
	for (u32 r = 0; r < tx_state->num_receivers; r++) {
		max_chunks_per_rcvr[r] = umin64(BATCH_SIZE, path_can_send_npkts(&tx_state->receiver[r].cc_states[tx_state->receiver[r].path_index]));
		total_chunks += max_chunks_per_rcvr[r];
	}
	return total_chunks;
}

// exclude receivers that have completed the current iteration
u32 exclude_completed_receivers(u32 *max_chunks_per_rcvr, const u32 *chunk_idx_per_rcvr, u32 total_chunks)
{
	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		if(chunk_idx_per_rcvr[r] == tx_state->total_chunks) {
			total_chunks -= max_chunks_per_rcvr[r];
			max_chunks_per_rcvr[r] = 0;
		}
	}
	return total_chunks;
}

// Send a total max of BATCH_SIZE
u32 shrink_sending_rates(u32 *max_chunks_per_rcvr, u32 total_chunks)
{
	if (total_chunks > BATCH_SIZE) {
		u32 new_total_chunks = 0; // due to rounding errors, we need to aggregate again
		for (u32 r = 0; r < tx_state->num_receivers; r++) {
			max_chunks_per_rcvr[r] = max_chunks_per_rcvr[r] * BATCH_SIZE / total_chunks;
			new_total_chunks += max_chunks_per_rcvr[r];
		}
		return new_total_chunks;
	}
	return total_chunks;
}

void prepare_rcvr_paths(const struct hercules_path **rcvr_path)
{
	for (u32 r = 0; r < tx_state->num_receivers; r++) {
		rcvr_path[r] = &tx_state->receiver[r].paths[tx_state->receiver[r].path_index];
	}
}

void iterate_paths()
{
	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		tx_state->receiver[r].path_index = (tx_state->receiver[r].path_index + 1) % tx_state->receiver[r].num_paths;
	}
}

static void terminate_cc(const struct sender_state_per_receiver *receiver)
{
	for(u32 i = 0; i < receiver->num_paths; i++) {
		terminate_ccontrol(&receiver->cc_states[i]);
	}
}

static void kick_cc(const bool *finished)
{
	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		if(finished[r]) {
			continue;
		}
		for(u32 p = 0; p < tx_state->receiver[r].num_paths; p++) {
			kick_ccontrol(&tx_state->receiver[r].cc_states[p]);
		}
	}
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
static void tx_only(struct xsk_socket_info *xsk)
{
	prev_rate_check = get_nsecs();
	u32 frame_nb = 0;
	u64 prev_round_start[tx_state->num_receivers];
	memset(prev_round_start, 0, sizeof(prev_round_start));
	u64 prev_round_end[tx_state->num_receivers];
	for (u32 r = 0; r < tx_state->num_receivers; r++) {
		prev_round_end[r] = prev_rate_check;
	}
	u64 prev_round_dt[tx_state->num_receivers];
	u64 slope[tx_state->num_receivers];
	memset(slope, 0, sizeof(slope)); // set slope to 0 for first round
	u64 ack_wait_duration_per_rcvr[tx_state->num_receivers]; // timeout after which a chunk is retransmitted. Allows for some lost ACKs.
	memset(ack_wait_duration_per_rcvr, 0, sizeof(ack_wait_duration_per_rcvr));
	bool finished[tx_state->num_receivers];
	memset(finished, false, sizeof(finished));
	u32 finished_count = 0;

	debug_printf("Start transmit round for all receivers\n");

#ifndef NDEBUG
	u32 round[tx_state->num_receivers];
	memset(round, 0, sizeof(round));
#endif
	u32 chunks[BATCH_SIZE];
	u32 chunk_rcvr[BATCH_SIZE];
	u32 max_chunks_per_rcvr[tx_state->num_receivers];
	u32 chunk_idx_per_rcvr[tx_state->num_receivers];
	memset(chunk_idx_per_rcvr, 0, sizeof(chunk_idx_per_rcvr));

	while(finished_count < tx_state->num_receivers)
	{
		u64 chunk_ack_due = 0;
		u32 num_chunks_per_rcvr[tx_state->num_receivers];
		memset(num_chunks_per_rcvr, 0, sizeof(num_chunks_per_rcvr));

		// path rate limits
		u32 total_chunks = compute_max_chunks_per_rcvr(max_chunks_per_rcvr);
		total_chunks = exclude_completed_receivers(max_chunks_per_rcvr, chunk_idx_per_rcvr, total_chunks);

		if(total_chunks == 0) { // we hit the rate limits on every path
			iterate_paths();
			continue;
		}

		// send a max of BATCH_SIZE chunks per iteration
		total_chunks = shrink_sending_rates(max_chunks_per_rcvr, total_chunks);

		// Select batch of un-ACKed chunks for retransmit:
		// Batch ends if an un-ACKed chunk is encountered for which we should keep
		// waiting a bit before retransmit.
		const u64 now = get_nsecs();
		u32 num_chunks = 0;
		for(u32 r = 0; finished_count < tx_state->num_receivers && num_chunks < total_chunks; r = (r + 1) % tx_state->num_receivers) {
			if(num_chunks_per_rcvr[r] >= max_chunks_per_rcvr[r] || finished[r]) {
				continue;
			}

			u32 prev_chunk_idx = chunk_idx_per_rcvr[r];
			chunk_idx_per_rcvr[r] = bitset__scan_neg(&tx_state->receiver[r].acked_chunks, chunk_idx_per_rcvr[r]);
			if(chunk_idx_per_rcvr[r] == tx_state->total_chunks) {
				if(prev_chunk_idx == 0) { // this receiver has finished
					debug_printf("receiver %d has finished\n", r);
					finished[r] = true;
					finished_count++;
					total_chunks -= max_chunks_per_rcvr[r] - num_chunks_per_rcvr[r]; // account for unused available bandwidth
					if (tx_state->receiver[0].cc_states) {
						terminate_cc(&tx_state->receiver[r]);
						kick_cc(finished);
					}
					continue;
				}

				// switch round for this receiver:
				debug_printf("Receiver %d enters retransmit round %u\n", r, round[r]++);

				chunk_idx_per_rcvr[r] = 0;
				prev_round_start[r] = prev_round_end[r];
				prev_round_end[r] = get_nsecs();
				prev_round_dt[r] = prev_round_end[r] - prev_round_start[r];
				slope[r] = (prev_round_dt[r] + tx_state->total_chunks - 1) / tx_state->total_chunks; // round up
				ack_wait_duration_per_rcvr[r] = 3 * (ACK_RATE_TIME_MS * 1000000UL + tx_state->receiver[r].handshake_rtt);

				// try again with this receiver
				r--;
				continue;
			}

			const u64 prev_transmit = umin64(prev_round_start[r] + slope[r] * chunk_idx_per_rcvr[r], prev_round_end[r]);
			const u64 ack_due = prev_transmit + ack_wait_duration_per_rcvr[r]; // 0 for first round
			if(now >= ack_due) {
				tx_state->receiver[r].path_map[chunk_idx_per_rcvr[r]] = tx_state->receiver[r].path_index;
				chunks[num_chunks] = chunk_idx_per_rcvr[r]++;
				chunk_rcvr[num_chunks] = r;
				num_chunks_per_rcvr[r]++;
				num_chunks++;
			} else {
				// skip this receiver in the current batch
				total_chunks -= max_chunks_per_rcvr[r] - num_chunks_per_rcvr[r];
				max_chunks_per_rcvr[r] = num_chunks_per_rcvr[r];

				// wait for the nearest ack
				if(chunk_ack_due) {
					if (chunk_ack_due > ack_due) {
						chunk_ack_due = ack_due;
					}
				} else {
					chunk_ack_due = ack_due;
				}
			}
		}

		if(num_chunks > 0) {
			const struct hercules_path *rcvr_path[tx_state->num_receivers];
			prepare_rcvr_paths(rcvr_path);
			send_batch(xsk, &frame_nb, rcvr_path, chunks, chunk_rcvr, num_chunks);
			rate_limit_tx();
		}
		iterate_paths();

		if(now < chunk_ack_due) {
			while(xsk->outstanding_tx && get_nsecs() < chunk_ack_due) {
				pop_completion_ring(xsk);
			}
			sleep_until(chunk_ack_due);
		}
	}
}

static void init_tx_state(size_t filesize, int chunklen, int max_rate_limit, char *mem, const struct hercules_app_addr *dests, const struct hercules_path *paths, u32 num_dests, const int *num_paths, u32 max_paths_per_dest)
{
	tx_state = calloc(1, sizeof(*tx_state));
	tx_state->filesize = filesize;
	tx_state->chunklen = chunklen;
	tx_state->total_chunks = (filesize + chunklen - 1)/chunklen;
	tx_state->mem = mem;
	tx_state->rate_limit = max_rate_limit;
	tx_state->start_time = 0;
	tx_state->end_time = 0;
	tx_state->num_receivers = num_dests;
	tx_state->receiver = calloc(num_dests, sizeof(*tx_state->receiver));

	for (u32 d = 0; d < num_dests; d++) {
		struct sender_state_per_receiver *receiver = &tx_state->receiver[d];
		bitset__create(&receiver->acked_chunks, tx_state->total_chunks);
		receiver->path_map = calloc(tx_state->total_chunks, sizeof(size_t));
		receiver->path_index = 0;
		receiver->handshake_rtt = 0;
		receiver->num_paths = num_paths[d];
		receiver->paths = calloc(receiver->num_paths, sizeof(struct hercules_path));
		receiver->addr = dests[d];
		receiver->cts_received = false;
		memcpy(receiver->paths, &paths[d * max_paths_per_dest], receiver->num_paths * sizeof(struct hercules_path));
	}
}

static void destroy_tx_state() {
	for (u32 d = 0; d < tx_state->num_receivers; d++) {
		struct sender_state_per_receiver *receiver = &tx_state->receiver[d];
		bitset__destroy(&receiver->acked_chunks);
		free(receiver->path_map);
		free(receiver->paths);
	}
	free(tx_state);
}

static struct receiver_state* make_rx_state(size_t filesize, int chunklen)
{
	struct receiver_state* r;
	r = calloc(1, sizeof(*r));
	r->filesize = filesize;
	r->chunklen = chunklen;
	r->total_chunks = (filesize + chunklen - 1)/chunklen;
	bitset__create(&r->received_chunks, r->total_chunks);
	r->start_time = 0;
	r->end_time = 0;
	return r;
}

static char *rx_mmap(const char *pathname, size_t filesize)
{
	int ret;
	ret = unlink(pathname);
	if (ret && errno != ENOENT) {
		exit_with_error(errno);
	}
	int f = open(pathname, O_RDWR|O_CREAT|O_EXCL, 0664);
	if (f == -1) {
		exit_with_error(errno);
	}
	ret = fallocate(f, 0, 0, filesize); // Will fail on old filesystems (ext3)
	if (ret) {
		exit_with_error(errno);
	}
	char *mem = mmap(NULL, filesize, PROT_WRITE, MAP_SHARED, f, 0);
	if (mem == MAP_FAILED) {
		exit_with_error(errno);
	}
	close(f);
	// fault and dirty the pages
	// This may be a terrible idea if filesize is larger than the available memory.
	// Note: MAP_POPULATE does NOT help when preparing for _writing_.
	int pagesize = getpagesize();
	for(ssize_t i = (ssize_t)filesize-1; i > 0; i -= pagesize) {
		mem[i] = 0;
	}
	return mem;
}

static bool rbudp_parse_initial(const char *pkt, size_t len, struct rbudp_initial_pkt *parsed_pkt)
{
	if(len < sizeof(*parsed_pkt)) {
		return false;
	}
	memcpy(parsed_pkt, pkt, sizeof(*parsed_pkt));

	return true;
}

static bool rx_get_reply_path(struct hercules_path *path)
{
	// Get reply path for sending ACKs:
	//
	// XXX: race reading from shared mem.
	// Try to make a quick copy to at least limit the carnage.
	if (!rx_state) {
		debug_printf("ERROR: invalid rx_state\n");
		return false;
	}
	int rx_sample_len = rx_state->rx_sample_len;
	assert(rx_sample_len > 0);
	assert(rx_sample_len <= XSK_UMEM__DEFAULT_FRAME_SIZE);
	char rx_sample_buf[XSK_UMEM__DEFAULT_FRAME_SIZE];
	memcpy(rx_sample_buf, rx_state->rx_sample_buf, rx_sample_len);

	int ret = HerculesGetReplyPath(rx_sample_buf, rx_sample_len, path);
	if (ret) {
		return false;
	}
	return true;
}

static void rx_send_rtt_ack(int sockfd, struct rbudp_initial_pkt *pld)
{
	struct hercules_path path;
	if(!rx_get_reply_path(&path)) {
		return;
	}

	char buf[ETHER_SIZE];
	void *rbudp_pkt = mempcpy(buf, path.header, path.headerlen);

	fill_rbudp_pkt(rbudp_pkt, UINT_MAX, (char*)pld, sizeof(*pld), path.payloadlen);
	stitch_checksum(&path, buf);

	send_eth_frame(sockfd, buf, path.framelen);
	tx_npkts++;
}

static bool rx_accept(int sockfd)
{
	char buf[ETHER_SIZE];
	while(true) { // Wait for well formed startup packet
		const char *payload;
		int payloadlen;
		if(recv_rbudp_control_pkt(sockfd, buf, ETHER_SIZE, &payload, &payloadlen, NULL, NULL)) {
			struct rbudp_initial_pkt parsed_pkt;
			if(rbudp_parse_initial(payload, payloadlen, &parsed_pkt)) {
				rx_state = make_rx_state(parsed_pkt.filesize, parsed_pkt.chunklen);
				if(!rx_state)
					return false;

				const size_t headerlen = payload - buf;
				set_rx_sample(rx_state, buf, headerlen + payloadlen);

				rx_send_rtt_ack(sockfd, &parsed_pkt); // echo back initial pkt to ACK filesize
				return true;
			}
		}
	}
}

static void rx_send_cts_ack(int sockfd)
{
	struct hercules_path path;
	if(!rx_get_reply_path(&path)) {
		return;
	}

	char buf[ETHER_SIZE];
	void *rbudp_pkt = mempcpy(buf, path.header, path.headerlen);

	struct rbudp_ack_pkt ack;
	ack.num_acks = 0;

	fill_rbudp_pkt(rbudp_pkt, UINT_MAX, (char*)&ack, ack__len(&ack), path.payloadlen);
	stitch_checksum(&path, buf);

	send_eth_frame(sockfd, buf, path.framelen);
	tx_npkts++;
}

static void rx_send_acks(int sockfd)
{
	struct hercules_path path;
	if(!rx_get_reply_path(&path)) {
		debug_printf("no reply path");
		return;
	}

	char buf[ETHER_SIZE];
	void *rbudp_pkt = mempcpy(buf, path.header, path.headerlen);

	// XXX: could write ack payload directly to buf, but
	// doesnt work nicely with existing fill_rbudp_pkt helper.
	struct rbudp_ack_pkt ack;

	const size_t max_entries = ack__max_num_entries(path.payloadlen - rbudp_headerlen);
	for(u32 curr = 0; curr < rx_state->total_chunks; )
	{
		// Data to send
		curr = fill_ack_pkt(curr, &ack, max_entries);
		if(ack.num_acks == 0) break;

		fill_rbudp_pkt(rbudp_pkt, UINT_MAX, (char*)&ack, ack__len(&ack), path.payloadlen);
		stitch_checksum(&path, buf);

		send_eth_frame(sockfd, buf, path.framelen);
		tx_npkts++;
	}
}

static void rx_trickle_acks(int sockfd)
{
	// XXX: data races in access to shared rx_state!
	while(!rx_received_all(rx_state))
	{
		rx_send_acks(sockfd);
		sleep_nsecs(ACK_RATE_TIME_MS * 1e6);
	}
}

static void *rx_p(void *arg)
{
	(void)arg;

	struct xsk_socket_info *xsk = (struct xsk_socket_info*)arg;
	submit_initial_rx_frames(xsk);

	while(running && !rx_received_all(rx_state)) {
		rx_receive_batch(xsk);
	}

	return NULL;
}

// Helper function: open a AF_PACKET socket and bind it to the given interface.
// @returns -1 on error
static int socket_on_if(int ifindex)
{
	int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (sockfd == -1) {
		return -1;
	}
	struct sockaddr_ll sockaddr;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sll_family = PF_PACKET;
	sockaddr.sll_protocol = htons(ETH_P_IP);
	sockaddr.sll_ifindex = ifindex;
	if (bind(sockfd, (struct sockaddr*) &sockaddr, sizeof(sockaddr)) == -1) {
		return -1;
	}
	return sockfd;
}

// XXX Workaround: the i40e driver (in zc mode) does not seem to allow sending if no program is loaded.
//	   Load an XDP program that just passes all packets (i.e. does the same thing as no program).
static int load_xsk_nop_passthrough()
{
	static const int log_buf_size = 16 * 1024;
	char log_buf[log_buf_size];
	int err, prog_fd;

	/* This is the C-program:
	 * SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
	 * {
	 *     return XDP_PASS;
	 * }
	 */
	struct bpf_insn prog[] = {
		BPF_MOV32_IMM(BPF_REG_0, 2),
		BPF_EXIT_INSN(),
	};
	size_t insns_cnt = sizeof(prog) / sizeof(struct bpf_insn);

	prog_fd = bpf_load_program(BPF_PROG_TYPE_XDP, prog, insns_cnt,
				   "LGPL-2.1 or BSD-2-Clause", 0, log_buf,
				   log_buf_size);
	if (prog_fd < 0) {
		printf("BPF log buffer:\n%s", log_buf);
		return prog_fd;
	}

	err = bpf_set_link_xdp_fd(opt_ifindex, prog_fd, opt_xdp_flags);
	if (err) {
		exit_with_error(-err);
	}
	return 0;
}

// XXX: taken and adapted from https://github.com/torvalds/linux/blob/master/tools/lib/bpf/xsk.c
static int xsk_lookup_current_xsks_map_fd(void)
{
	__u32 i, *map_ids, num_maps, info_len = sizeof(struct bpf_prog_info);
	__u32 map_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info prog_info = {};
	struct bpf_map_info map_info;
	int fd, err;

	int prog_fd = bpf_prog_get_fd_by_id(prog_id);
	if (prog_fd < 0)
		return -prog_fd;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &info_len);
	if (err)
		return err;

	num_maps = prog_info.nr_map_ids;

	map_ids = calloc(prog_info.nr_map_ids, sizeof(*map_ids));
	if (!map_ids)
		return -ENOMEM;

	memset(&prog_info, 0, info_len);
	prog_info.nr_map_ids = num_maps;
	prog_info.map_ids = (__u64)(unsigned long)map_ids;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &info_len);
	if (err)
		goto out_map_ids;

	int ret = -1;
	for (i = 0; i < prog_info.nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			continue;

		err = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (err) {
			close(fd);
			continue;
		}

		if (!strcmp(map_info.name, "xsks_map")) {
			ret = fd;
			continue;
		}

		close(fd);
	}

	if (ret == -1)
		ret = -ENOENT;

out_map_ids:
	free(map_ids);
	return ret;
}

/*
 * Replace the default program provided by the kernel with a program only redirecting IP
 * traffic to the XSK.
 */
static void load_xsk_redirect_userspace(void)
{
	static const int log_buf_size = 16 * 1024;
	char log_buf[log_buf_size];
	int err, prog_fd;

	int xsks_map_fd = xsk_lookup_current_xsks_map_fd();
	if (xsks_map_fd < 0) {
		exit_with_error(xsks_map_fd);
	}

	/* This is the C-program:
	 * SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
	 * {
	 *	   void *data = (void *)(long)ctx->data;
	 *	   void *data_end = (void *)(long)ctx->data_end;
	 *
	 * 	   if(data + sizeof(struct ether_header) + sizeof(struct iphdr) > data_end) {
	 *         return XDP_PASS; // too short
	 *     }
	 *     const struct ether_header *eh = (const struct ether_header *)data;
	 *     if(eh->ether_type != htons(ETHERTYPE_IP)) {
	 *         return XDP_PASS; // not IP
	 *     }
	 *
	 *	   return bpf_redirect_map(&xsks_map, 0, 0);
     * }
	 */
	struct bpf_insn prog[] = {
			/* r0 = XDP_PASS */
			BPF_MOV64_IMM(BPF_REG_0, 2),
			/* r3 = *(u32 *)(r1 + 4) */
			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, 4),
			/* r2 = *(u32 *)(r1 + 0) */
			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 0),
			/* r4 = r2 */
			BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
			/* r4 += 34 */
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 34),
			/* if r4 > r3 goto pc+20 */
			BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, 13),
			/* r3 = *(u8 *)(r2 + 12) */
			BPF_LDX_MEM(BPF_B, BPF_REG_3, BPF_REG_2, 12),
			/* r2 = *(u8 *)(r2 + 13) */
			BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_2, 13),
			/* r2 <<= 8 */
			BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 8),
			/* r2 |= r3 */
			BPF_ALU64_REG(BPF_OR, BPF_REG_2, BPF_REG_3),
			/* if r2 != htons(ETHERTYPE_IP) goto pc+15 */
			BPF_JMP_IMM(BPF_JNE, BPF_REG_2, htons(ETHERTYPE_IP), 8),
			/* r1 = r0 */
			BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
			/* r0 = XPF_PASS */
			BPF_MOV64_IMM(BPF_REG_0, 2),
			/* if r1 == 0 goto pc+5 */
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 5),
			/* r2 = *(u32 *)(r10 - 4) */
			BPF_MOV64_IMM(BPF_REG_2, opt_queue),
			/* r1 = xskmap[] */
			BPF_LD_MAP_FD(BPF_REG_1, xsks_map_fd),
			/* r3 = 0 */
			BPF_MOV64_IMM(BPF_REG_3, 0),
			/* call bpf_map_lookup_elem */
			BPF_EMIT_CALL(BPF_FUNC_redirect_map),
			/* The jumps are to this instruction */
			BPF_EXIT_INSN(),
	};
	size_t insns_cnt = sizeof(prog) / sizeof(struct bpf_insn);

	prog_fd = bpf_load_program(BPF_PROG_TYPE_XDP, prog, insns_cnt,
							   "LGPL-2.1 or BSD-2-Clause", 0, log_buf,
							   log_buf_size);
	if (prog_fd < 0) {
		printf("BPF log buffer:\n%s", log_buf);
		exit_with_error(-prog_fd);
	}

	// swap the programs
	remove_xdp_program();
	err = bpf_set_link_xdp_fd(opt_ifindex, prog_fd, opt_xdp_flags);
	if (err) {
		exit_with_error(-err);
	}
	err = bpf_get_link_xdp_id(opt_ifindex, &prog_id, opt_xdp_flags);
	if (err) {
		exit_with_error(-err);
	}
}

static void *tx_p(void *arg)
{
	int xdp_mode = *(int *)arg;

	load_xsk_nop_passthrough();
	struct xsk_socket_info *xsk = create_xsk_with_umem(XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, xdp_mode);
	tx_only(xsk);
	close_xsk(xsk);

	return NULL;
}

void hercules_init(int ifindex, const struct hercules_app_addr local_addr_, int queue)
{
	static char if_name_buf[IF_NAMESIZE];
	opt_ifindex = ifindex;

	if_indextoname(ifindex, if_name_buf);
	opt_ifname = if_name_buf; // XXX urrgh
	opt_queue = queue;

	local_addr = local_addr_;

	debug_printf("ifindex: %i, queue %i", opt_ifindex, opt_queue);

	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	setlocale(LC_ALL, "");
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

}

static struct hercules_stats tx_stats(struct sender_state *t) {
	u32 completed_chunks = 0;
	for(u32 r = 0; r < tx_state->num_receivers; r++) {
		completed_chunks += t->receiver[r].acked_chunks.num_set;
	}
	return (struct hercules_stats){
		.start_time = t->start_time,
		.end_time = t->end_time,
		.now = get_nsecs(),
		.tx_npkts = tx_npkts,
		.rx_npkts = rx_npkts,
		.filesize = t->filesize,
		.framelen = t->receiver[0].paths[0].framelen,
		.chunklen = t->chunklen,
		.total_chunks = t->total_chunks * t->num_receivers,
		.completed_chunks = completed_chunks,
		.rate_limit = t->rate_limit
	};
}

static struct hercules_stats rx_stats(struct receiver_state *r) {
	return (struct hercules_stats){
		.start_time = r->start_time,
		.end_time = r->end_time,
		.now = get_nsecs(),
		.tx_npkts = tx_npkts,
		.rx_npkts = rx_npkts,
		.filesize = r->filesize,
		.framelen = r->rx_sample_len,
		.chunklen = r->chunklen,
		.total_chunks = r->total_chunks,
		.completed_chunks = r->received_chunks.num_set,
		.rate_limit = 0
	};
}

struct hercules_stats hercules_get_stats()
{
	if(!tx_state && !rx_state) {
		return (struct hercules_stats){
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
	if (ret)
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

struct hercules_stats
hercules_tx(const char* filename, const struct hercules_app_addr *destinations, const struct hercules_path *paths_per_dest, int num_dests, const int *num_paths, int max_paths, int max_rate_limit, bool enable_pcc, int xdp_mode)
{
	// Open mmaped send file
	int f = open(filename, O_RDONLY);
	if (f == -1) {
		exit_with_error(errno);
	}

	struct stat stat;
	int ret = fstat(f, &stat);
	if(ret) {
		exit_with_error(errno);
	}
	const size_t filesize = stat.st_size;

	char *mem = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE|MAP_POPULATE, f, 0);
	if (mem == MAP_FAILED) {
		fprintf(stderr, "ERR: memory mapping failed\n");
		exit_with_error(errno);
	}
	close(f);

	u32 chunklen = paths_per_dest[0].payloadlen - rbudp_headerlen;
	for (int r = 0; r < num_dests; r++) {
		for (int i = 0; i < num_paths[r]; i++) {
			chunklen = umin32(chunklen, paths_per_dest[r * max_paths + i].payloadlen - rbudp_headerlen);
		}
	}
	init_tx_state(filesize, chunklen, max_rate_limit, mem, destinations, paths_per_dest, num_dests, num_paths, max_paths);

	// Open RAW socket for control messages
	int sockfd = socket_on_if(opt_ifindex);
	if (sockfd == -1) {
		exit_with_error(errno);
	}

	if(!tx_handshake(sockfd)) {
		exit_with_error(ETIMEDOUT);
	}

	if(enable_pcc) {
		for (int i = 0; i < num_dests; i++) {
			struct sender_state_per_receiver *receiver = &tx_state->receiver[i];
			receiver->cc_states = init_ccontrol_state(
					max_rate_limit,
					receiver->handshake_rtt,
					tx_state->total_chunks,
					num_paths[i]
			);
			debug_printf("handshake_rtt (receiver %d): %fs, MI: %fs",
					i, receiver->handshake_rtt / 1e9, receiver->cc_states[i].pcc_mi_duration);
		}
	}

	tx_state->rate_limit = max_rate_limit;

	// Wait for CTS from receiver
	printf("Waiting for receiver to get ready..."); fflush(stdout);
	if(!tx_await_cts(sockfd)) {
		exit_with_error(ETIMEDOUT);
	}
	printf(" OK\n");

	tx_state->start_time = get_nsecs();
	running = true;
	pthread_t worker = start_thread(tx_p, &xdp_mode);

	tx_recv_acks(sockfd);

	tx_state->end_time = get_nsecs();
	running = false;
	join_thread(worker);

	struct hercules_stats stats = tx_stats(tx_state);

	if (enable_pcc) {
		for (int i = 0; i < num_dests; i++) {
			destroy_ccontrol_state(tx_state->receiver[i].cc_states, num_paths[i]);
		}
	}
	destroy_tx_state();
	close(sockfd);

	return stats;
}

struct hercules_stats
hercules_rx(const char *filename, int xdp_mode)
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
	debug_printf("Filesize %lu Bytes, %u total chunks of size %u.",
			rx_state->filesize, rx_state->total_chunks, rx_state->chunklen);
	printf("Preparing file for receive..."); fflush(stdout);
	rx_state->mem = rx_mmap(filename, rx_state->filesize);
	printf(" OK\n");

	// attempt to load the default BPF program redirecting all traffic to the XSK
	struct xsk_socket_info *xsk = create_xsk_with_umem(0, xdp_mode);
	// swap the program while keeping the xsks_map
	load_xsk_redirect_userspace();

	rx_state->start_time = get_nsecs();
	running = true;
	pthread_t worker = start_thread(rx_p, xsk);

	rx_send_cts_ack(sockfd); // send Clear To Send ACK
	rx_trickle_acks(sockfd);
	rx_send_acks(sockfd);

	rx_state->end_time = get_nsecs();
	running = false;
	join_thread(worker);

	struct hercules_stats stats = rx_stats(rx_state);

	close_xsk(xsk);
	bitset__destroy(&rx_state->received_chunks);
	free(rx_state);
	close(sockfd);
	return stats;
}

void hercules_close()
{
	// Only essential cleanup.
	remove_xdp_program();
}
