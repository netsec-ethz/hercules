// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2017 - 2018 Intel Corporation.
// Copyright(c) 2019 ETH Zurich.

// Enable extra warnings; cannot be enabled in CFLAGS because cgo generates a
// ton of warnings that can apparantly not be suppressed.
#pragma GCC diagnostic warning "-Wextra"

#include "hercules.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdatomic.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
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
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
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

struct sender_state {
	/** Filesize in bytes */
	size_t filesize;
	/** Size of file data (in byte) per packet */
	u32 chunklen;
	/** Number of packets that will make up the entire file. Equal to `ceil(filesize/chunklen)` */
	u32 total_chunks;
	/** Memory mapped file for receive */
	char *mem;

	struct bitset acked_chunks;

	u64 handshake_rtt; // Handshake RTT in ns
	_Atomic u32 rate_limit;

	// Start/end time of the current transfer
	u64 start_time;
	u64 end_time;
};

struct sender_path_state {
    struct hercules_path path;
    struct ccontrol_state *cc_state;
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
static struct sender_path_state *path_state_for_stats; // TODO get rid of this workaround

// State for transmit rate control
static size_t tx_npkts;
static size_t prev_rate_check;
static size_t prev_tx_npkts;
// State for receive rate, for stat dump only
static size_t rx_npkts;

static bool running;


static void fill_rbudp_pkt(void *rbudp_pkt, u32 chunk_idx, const char *data, size_t n, size_t payloadlen);
static bool rbudp_parse_initial(const char *pkt, size_t len, struct rbudp_initial_pkt *parsed_pkt);
static void stitch_checksum(const struct hercules_path *path, char *pkt);

static bool rx_received_all(const struct receiver_state *r) {
	return (r->received_chunks.num_set == r->total_chunks);
}

static bool tx_acked_all(const struct sender_state *t) {
	return (t->acked_chunks.num_set == t->total_chunks);
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
// return rbudp-packet (i.e. SCION/UDP packet payload)
static const char* parse_pkt(const char *pkt, size_t length, bool check)
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

	if (check) {
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
	return pkt + offset;
}

static bool recv_rbudp_control_pkt(int sockfd, char *buf, size_t buflen, const char **payload, int *payloadlen)
{
	ssize_t len = recv(sockfd, buf, buflen, 0); // XXX set timeout
	if(len == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			return false;
		}
		exit_with_error(errno); // XXX: are there situations where we want to try again?
	}

	const char *rbudp_pkt = parse_pkt(buf, len, true);
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
	if (length != rbudp_headerlen + rx_state->chunklen) {
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

static void tx_register_acks(const struct rbudp_ack_pkt *ack, const struct sender_path_state *path_state)
{
	for(uint16_t e = 0; e < ack->num_acks; ++e)
	{
		const u32 begin = ack->acks[e].begin;
		const u32 end   = ack->acks[e].end;
		if(begin >= end || end > tx_state->total_chunks) {
			return; // Abort
		}
		for(u32 i = begin; i < end; ++i) { // XXX: this can *obviously* be optimized
			bitset__set(&tx_state->acked_chunks, i);
		}
		if (path_state->cc_state) {
			// Counts ACKed packets from the range that was sent during the MI.
			// ack_start is the packet with the lowest index sent during the MI,
			// ack_end the packet with the highest index that could have been sent during the MI
			// TODO: Improve the granularity of the accounting of the ACKed packets during a MI
			// if required by the CC algorithm.
			const u32 begin_cc = umax32(begin, path_state->cc_state->ack_start);
			const u32 end_cc = umin32(end, path_state->cc_state->ack_end + 1);
			for(u32 i = begin_cc; i < end_cc; ++i) {
				bitset__set(&path_state->cc_state->mi_acked_chunks, i);
			}
		}
	}
}

static bool pcc_mi_elapsed(const struct sender_path_state *path_state)
{
	unsigned long now = get_nsecs();
	unsigned long dt = now - path_state->cc_state->mi_start;
	return dt > (path_state->cc_state->pcc_mi_duration + path_state->cc_state->rtt) * 1e9;
}

static void pcc_monitor(const struct sender_path_state *path_state)
{
	if (pcc_mi_elapsed(path_state)) {
		u32 sent_mi = path_state->cc_state->curr_rate * path_state->cc_state->pcc_mi_duration; // pkts sent in MI
		u32 acked_mi = path_state->cc_state->mi_acked_chunks.num_set; // acked pkts from MI

		sent_mi = umax32(sent_mi, 1);
		acked_mi = umin32(acked_mi, sent_mi);
		float loss = (sent_mi - acked_mi) / sent_mi;
		float throughput = path_state->cc_state->curr_rate * (1 - loss);

		u32 new_rate = pcc_control(path_state->cc_state, throughput, loss);
		tx_state->rate_limit = new_rate; // Update atomic rate_limit, only read from tx_only

		bool retransmitting = tx_npkts > tx_state->total_chunks;
		// Reset MI state info, only safe because no acks are processed during those updates
		bitset__reset(&path_state->cc_state->mi_acked_chunks);
		if (!retransmitting) {
			path_state->cc_state->ack_start = tx_npkts;
			path_state->cc_state->ack_end = path_state->cc_state->ack_start + new_rate * path_state->cc_state->pcc_mi_duration; // misses acks from a MI straddling initial transmissions and retransmission (efficiency trade-off)
		} else {
			// overestimates the number of pkts sent during MI (tx_state->cc_state->mi_start not yet updated)
			path_state->cc_state->ack_start =  bitset__scan_neg(&tx_state->acked_chunks, 0);
			// underestimates the number of pkts sent during MI (does not wrap)
			path_state->cc_state->ack_end = bitset__scan_neg_n(&tx_state->acked_chunks, path_state->cc_state->ack_start, new_rate * path_state->cc_state->pcc_mi_duration);
		}

		path_state->cc_state->mi_start = get_nsecs(); // start new MI
	}
}

static void tx_recv_acks(int sockfd, const struct sender_path_state *state)
{
	struct timeval to = { .tv_sec = 0, .tv_usec = 100 };
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

	char buf[ETHER_SIZE];
	while (!tx_acked_all(tx_state)) {
		const char *payload;
		int payloadlen;
		if(recv_rbudp_control_pkt(sockfd, buf, ETHER_SIZE, &payload, &payloadlen)) {
			const struct rbudp_ack_pkt *ack = (const struct rbudp_ack_pkt*)payload;
			if((u32)payloadlen >= ack__len(ack)) {
                tx_register_acks(ack, state);
			}
		}

		if(state->cc_state) {
            pcc_monitor(state);
		}
	}
}

static bool tx_await_cts(int sockfd)
{
	// Set 20 second timeout on the socket, wait for receiver to get ready
	struct timeval to = { .tv_sec = 20, .tv_usec = 0 };
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

	char buf[ETHER_SIZE];
	const char *payload;
	int payloadlen;
	for(int i = 0; i < tx_handshake_retries; ++i) {
		if(recv_rbudp_control_pkt(sockfd, buf, ETHER_SIZE, &payload, &payloadlen)) {
			const struct rbudp_ack_pkt *ack = (const struct rbudp_ack_pkt*)payload;
			if(ack->num_acks == 0) {
				return true;
			}
		}
	}
	return false;
}

static bool tx_await_rtt_ack(int sockfd)
{
	// Set 1 second timeout on the socket
	struct timeval to = { .tv_sec = 1, .tv_usec = 0 };
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

	char buf[ETHER_SIZE];
	const char *payload;
	int payloadlen;
	if(recv_rbudp_control_pkt(sockfd, buf, ETHER_SIZE, &payload, &payloadlen)) {
		struct rbudp_initial_pkt parsed_pkt;
		if(rbudp_parse_initial(payload, payloadlen, &parsed_pkt)) {
			tx_state->handshake_rtt = (u64)(get_nsecs() - parsed_pkt.timestamp);
			if (parsed_pkt.filesize != tx_state->filesize ||
				parsed_pkt.chunklen != tx_state->chunklen) {
					debug_printf("Receiver disagrees "
						"on transfer parameters:\n"
						"filesize: %llu\nchunklen: %u",
						parsed_pkt.filesize,
						parsed_pkt.chunklen);
					return false;
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

static bool tx_handshake(int sockfd, const struct sender_path_state *path_state)
{
	for(int i = 0; i < tx_handshake_retries; ++i) {
		unsigned long timestamp = get_nsecs();
		tx_send_initial(sockfd, &path_state->path, tx_state->filesize, tx_state->chunklen, timestamp);
		if(tx_await_rtt_ack(sockfd)) {
			return true;
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
		const char *rbudp_pkt = parse_pkt(pkt, len, true);
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

static void send_batch(struct xsk_socket_info *xsk, u32 *frame_nb, const struct hercules_path *path, const u32 chunks[], u32 num_chunks)
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

	u32 i;
	for (i = 0; i < num_chunks; ++i)
	{
		char *pkt = produce_frame(xsk, *frame_nb + i, idx + i, path->framelen);

		const u32 chunk_idx = chunks[i];
		const size_t chunk_start = (size_t)chunk_idx * tx_state->chunklen;
		const size_t len = umin64(tx_state->chunklen, tx_state->filesize - chunk_start);

		// TODO put path header
		fill_rbudp_pkt(pkt + path->headerlen, chunk_idx, tx_state->mem + chunk_start, len, path->payloadlen);
		stitch_checksum(path, pkt);
	}
	submit_batch(xsk, frame_nb, i);
}

// TODO obsolete
static void splat_path(struct xsk_socket_info *xsk, const struct hercules_path *path) {
	// splat header into umem
	void *buffer = xsk->umem->buffer;
	for (int f = 0; f < NUM_FRAMES; ++f) {
		memcpy(xsk_umem__get_data(buffer, f * XSK_UMEM__DEFAULT_FRAME_SIZE), path->header, path->headerlen);
	}
}


// Initial transmit round
// Send each chunk once
static void tx_transmit_round(struct xsk_socket_info *xsk, u32 *frame_nb, const struct hercules_path *path)
{
	u32 chunks[BATCH_SIZE];
	for (u32 chunk_idx = 0; chunk_idx < tx_state->total_chunks; ) {
		// TODO: check for new path; splat again if necessary

		// Pass consecutive chunk ids to send_batch
		int i;
		for(i = 0; i < BATCH_SIZE && chunk_idx < tx_state->total_chunks; ++i) {
			chunks[i] = chunk_idx++;
		}
		send_batch(xsk, frame_nb, path, chunks, i);
		rate_limit_tx(); // TODO refactor rate limit to consider different paths
	}
}

/**
 * Retransmit chunks that have not been ACKed.
 * For each retransmit chunk, wait (at least) one round trip time for the ACK to arrive.
 * For large files transfers, this naturally allows to start retransmitting chunks at the beginning
 * of the file, while chunks of the previous round at the end of the file are still in flight.
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
 * and linearly interpolate.
 * This assumes a uniform send rate and that chunks that need to be retransmitted (i.e. losses)
 * occur uniformly.
 */
static void tx_retransmit_round(struct xsk_socket_info *xsk, u32 *frame_nb, const struct hercules_path *path, u64 prev_round_start, u64 prev_round_end)
{
	const u64 prev_round_dt = prev_round_end - prev_round_start;
	const u64 slope = (prev_round_dt + tx_state->total_chunks - 1) / tx_state->total_chunks; // round up
	const u64 ack_wait_duration = 3 * (ACK_RATE_TIME_MS * 1000000UL + tx_state->handshake_rtt); // timeout after which a chunk is retransmitted. Allows for some lost ACKs.

	u32 chunks[BATCH_SIZE];
	for(u32 chunk_idx = 0; chunk_idx < tx_state->total_chunks; )
	{
		u64 chunk_ack_due = 0;
		u32 num_chunks = 0;

		// Select batch of un-ACKed chunks for retransmit:
		// Batch ends if an un-ACKed chunk is encountered for which we should keep
		// waiting a bit before retransmit.
		const u64 now = get_nsecs();
		for(u32 i = 0; i < BATCH_SIZE; ++i) {
			chunk_idx = bitset__scan_neg(&tx_state->acked_chunks, chunk_idx);
			if(chunk_idx == tx_state->total_chunks) {
				num_chunks = i;
				break;
			}

			const u64 prev_transmit = umin64(prev_round_start + slope * chunk_idx, prev_round_end);
			const u64 ack_due = prev_transmit + ack_wait_duration;
			if(now >= ack_due) {
				chunks[i] = chunk_idx++;
				num_chunks = i+1;
			} else {
				num_chunks = i;
				chunk_ack_due = ack_due;
				break;
			}
		}

		if(num_chunks > 0) {
			send_batch(xsk, frame_nb, path, chunks, num_chunks);
			rate_limit_tx();
		}

		if(now < chunk_ack_due) {
			while(xsk->outstanding_tx && get_nsecs() < chunk_ack_due) {
				pop_completion_ring(xsk);
			}
			sleep_until(chunk_ack_due);
		}
	}
}

static void tx_only(struct xsk_socket_info *xsk, const struct sender_path_state *path_state)
{
	const struct hercules_path *path = &path_state->path;
    splat_path(xsk, path);

	prev_rate_check = get_nsecs();
	u64 prev_round_start = prev_rate_check;

	u32 frame_nb = 0;
	tx_transmit_round(xsk, &frame_nb, path);

	debug_printf("Starting retransmit");
#ifndef NDEBUG
	u32 r = 0;
#endif
	while (running) {
		u64 curr_round_start = get_nsecs();

		debug_printf("Retransmit round %u", r++);
		tx_retransmit_round(xsk, &frame_nb, path, prev_round_start, curr_round_start);

		prev_round_start = curr_round_start;
	}
}

static void init_tx_state(size_t filesize, int chunklen, int max_rate_limit, char *mem)
{
	tx_state = calloc(1, sizeof(*tx_state));
	tx_state->filesize = filesize;
	tx_state->chunklen = chunklen;
	tx_state->total_chunks = (filesize + chunklen - 1)/chunklen;
	bitset__create(&tx_state->acked_chunks, tx_state->total_chunks);
	tx_state->mem = mem;
	tx_state->handshake_rtt = 0.1; // Arbitrary nz init value
	tx_state->rate_limit = max_rate_limit;
	tx_state->start_time = 0;
	tx_state->end_time = 0;
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
		if(recv_rbudp_control_pkt(sockfd, buf, ETHER_SIZE, &payload, &payloadlen)) {
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

struct tx_p_args {
	int xdp_mode;
	const struct sender_path_state *path_state;
};

static void *tx_p(void *arg)
{
	struct tx_p_args *args = (struct tx_p_args *)arg;

	load_xsk_nop_passthrough();
	struct xsk_socket_info *xsk = create_xsk_with_umem(XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, args->xdp_mode);
	tx_only(xsk, args->path_state);
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

static struct hercules_stats tx_stats(struct sender_state *t, const struct sender_path_state *path_state) {
	return (struct hercules_stats){
		.start_time = t->start_time,
		.end_time = t->end_time,
		.now = get_nsecs(),
		.tx_npkts = tx_npkts,
		.rx_npkts = rx_npkts,
		.filesize = t->filesize,
		.framelen = path_state->path.framelen,
		.chunklen = t->chunklen,
		.total_chunks = t->total_chunks,
		.completed_chunks = t->acked_chunks.num_set,
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
		// TODO use all paths for stats
		return tx_stats(tx_state, path_state_for_stats);
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
hercules_tx(const char* filename, const struct hercules_path *path, int max_rate_limit, bool enable_pcc, int xdp_mode)
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

	const size_t chunklen = path->payloadlen - rbudp_headerlen;
	init_tx_state(filesize, chunklen, max_rate_limit, mem);

	struct sender_path_state *path_state = calloc(1, sizeof(struct sender_path_state));
	path_state_for_stats = path_state; // TODO get rid of this workaround
	memcpy(&path_state->path, path, sizeof(struct hercules_path));

	// Open RAW socket for control messages
	int sockfd = socket_on_if(opt_ifindex);
	if (sockfd == -1) {
		exit_with_error(errno);
	}

	if(!tx_handshake(sockfd, path_state)) {
		exit_with_error(ETIMEDOUT);
	}

	if(enable_pcc) {
		path_state->cc_state = init_ccontrol_state(max_rate_limit, tx_state->handshake_rtt, tx_state->total_chunks);
	}

	if (path_state->cc_state) {
		debug_printf("handshake_rtt: %fs, MI: %fs", tx_state->handshake_rtt/1e9, path_state->cc_state->pcc_mi_duration);
		tx_state->rate_limit = path_state->cc_state->curr_rate; // Set initial send rate for PCC
	} else {
		tx_state->rate_limit = max_rate_limit;
	}

	// Wait for CTS from receiver
	printf("Waiting for receiver to get ready..."); fflush(stdout);
	if(!tx_await_cts(sockfd)) {
		exit_with_error(ETIMEDOUT);
	}
	printf(" OK\n");

	tx_state->start_time = get_nsecs();
	running = true;
	struct tx_p_args args = {
	        xdp_mode,
	        path_state,
	};
	pthread_t worker = start_thread(tx_p, &args);

	tx_recv_acks(sockfd, path_state);

	tx_state->end_time = get_nsecs();
	running = false;
	join_thread(worker);

	struct hercules_stats stats = tx_stats(tx_state, path_state);

	bitset__destroy(&tx_state->acked_chunks);
	free(path_state->cc_state);
	free(tx_state);
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

	struct xsk_socket_info *xsk = create_xsk_with_umem(0, xdp_mode);

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
