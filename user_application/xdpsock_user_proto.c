// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2018 Intel Corporation. */

//
#define _GNU_SOURCE
//

#include <asm/barrier.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/compiler.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "bpf/libbpf.h"
#include "bpf/xsk.h"
#include <bpf/bpf.h>

//
#include <sched.h>
#include <sys/stat.h>
#include <fcntl.h>
//

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define NUM_FRAMES (4 * 1024)
#define BATCH_SIZE 64

#define DEBUG_HEXDUMP 1
#define MAX_SOCKS 8

//
#define ETHER_SIZE 1500
#define RATE_LIMIT 200000 // rate limit for tx,  in packets per second
#define RATE_LIMIT_CHECK 1000 // check rate limit every X packets (Maximum burst above target pps allowed)

int fh_rx;
void *mmpb_rx;
void *mmpi_rx;

int fh_tx;
void *mmpb_tx;
void *mmpi_tx;
//

typedef __u64 u64;
typedef __u32 u32;

static unsigned long prev_time;
//
static unsigned long prev_dump;
static unsigned long prev_rate_check;

static unsigned long global_tx_npkts;
static unsigned long prev_global_tx_npkts;

static unsigned long msize = 1024UL * 1024 * 1024 * 5;

static int l4_header_size = 42;
//

enum benchmark_type {
	BENCH_RXDROP = 0,
	BENCH_TXONLY = 1,
	BENCH_RXTX = 2,
};

//
enum host_type {
	HOST_A = 0,
	HOST_B = 1,
};
//

static enum benchmark_type opt_bench = BENCH_RXTX;
//
static enum host_type opt_host = HOST_A;
//
static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static const char *opt_if = "";
static int opt_ifindex;
static int opt_queue;
static int opt_poll;
static int opt_interval = 1;
//
static int opt_duration = 0;
//
static u32 opt_xdp_bind_flags;
static __u32 prog_id;

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
	unsigned long rx_npkts;
	unsigned long tx_npkts;
	unsigned long prev_rx_npkts;
	unsigned long prev_tx_npkts;
	u32 outstanding_tx;
};

static int num_socks;
struct xsk_socket_info *xsks[MAX_SOCKS];


static const char header_A[] =
	"\x3c\xfd\xfe\x9e\x93\x41\x3c\xfd\xfe\x9e\x99\x51\x08\x00\x45\x00"
	"\x05\xcc\x00\x00\x00\x00\x40\x11\x88\x97\xac\x10\x2a\x02\xac\x10"
	"\x2a\x01\x10\x92\x10\x92\x05\xaa\x6d\xa3\x41\x41\x41\x41\x41\x41";

static const char header_B[] =
	"\x3c\xfd\xfe\x9e\x99\x51\x3c\xfd\xfe\x9e\x93\x41\x08\x00\x45\x00"
	"\x05\xcc\x00\x00\x00\x00\x40\x11\x88\x97\xac\x10\x2a\x01\xac\x10"
	"\x2a\x02\x10\x92\x10\x92\x05\xaa\x6d\xa3\x41\x41\x41\x41\x41\x41";

static char pkt_data[ETHER_SIZE];

static void dump_stats(void);
static void int_exit(int sig);

static unsigned long get_nsecs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static void print_benchmark(bool running)
{
	const char *bench_str = "INVALID";

	if (opt_bench == BENCH_RXDROP)
		bench_str = "rxdrop";
	else if (opt_bench == BENCH_TXONLY)
		bench_str = "txonly";
	else if (opt_bench == BENCH_RXTX)
		bench_str = "rxtx";

	printf("%s:%d %s ", opt_if, opt_queue, bench_str);
	if (opt_xdp_flags & XDP_FLAGS_SKB_MODE)
		printf("xdp-skb ");
	else if (opt_xdp_flags & XDP_FLAGS_DRV_MODE)
		printf("xdp-drv ");
	else
		printf("	");

	if (opt_poll)
		printf("poll() ");

	if (running) {
		printf("running...");
		fflush(stdout);
	}
}

static void dump_stats(void)
{
	unsigned long now = get_nsecs();
	long dt = now - prev_time;
	int i;

	prev_time = now;

	for (i = 0; i < num_socks && xsks[i]; i++) {
		char *fmt = "%-15s %'-11.0f %'-11lu\n";
		double rx_pps, tx_pps;

		rx_pps = (xsks[i]->rx_npkts - xsks[i]->prev_rx_npkts) *
			 1000000000. / dt;
		tx_pps = (xsks[i]->tx_npkts - xsks[i]->prev_tx_npkts) *
			 1000000000. / dt;

		printf("\n sock%d@", i);
		print_benchmark(false);
		printf("\n");

		printf("%-15s %-11s %-11s %-11.2f\n", "", "pps", "pkts",
		       dt / 1000000000.);
		printf(fmt, "rx", rx_pps, xsks[i]->rx_npkts);
		printf(fmt, "tx", tx_pps, xsks[i]->tx_npkts);

		xsks[i]->prev_rx_npkts = xsks[i]->rx_npkts;
		xsks[i]->prev_tx_npkts = xsks[i]->tx_npkts;
	}
}

static void *poller(void *arg)
{
	(void)arg;
	int i;
	for (i=0; i<opt_duration || opt_duration == 0; i++) {
		sleep(opt_interval);
		dump_stats();
	}
	int_exit(0);

	return NULL;
}

static void remove_xdp_program(void)
{
	__u32 curr_prog_id = 0;

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

static void int_exit(int sig)
{
	struct xsk_umem *umem = xsks[0]->umem->umem;

	(void)sig;

	dump_stats();
	xsk_socket__delete(xsks[0]->xsk);
	(void)xsk_umem__delete(umem);
	remove_xdp_program();

	exit(EXIT_SUCCESS);
}

static void __exit_with_error(int error, const char *file, const char *func,
			      int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func,
		line, error, strerror(error));
	dump_stats();
	remove_xdp_program();
	exit(EXIT_FAILURE);
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, \
						 __LINE__)

static void write_to_file(void *pkt, int length)
{
	// to memory
	size_t offset = l4_header_size;
	const void *mb = (void *)(pkt + offset);
	size_t outlen = length - offset;
	if ((mmpi_rx + outlen) >= (mmpb_rx + msize)) {
		printf("mmpi_rx = %p, mmpb_rx = %p, mmpb_rx++ = %p\n", mmpi_rx, mmpb_rx, mmpb_rx + msize);
		mmpi_rx = mmpb_rx;
		return;
		// for ring file, remove the return above

		// Add some marker when wrapping around
		static const char marker_data[] =
			"\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42";
		mmpi_rx = mempcpy(mmpi_rx, marker_data, 16);
	}

	mmpi_rx = mempcpy(mmpi_rx, mb, outlen);
	//mmpi_rx = mempcpy(pkt_data, mb, outlen);

	//printf("Wrote to mfile: %d\n", outlen);
}

static void preheat_mem(void)
{
	// write to memory to make sure it is in the cache
	while ((mmpi_rx + 16) <= (mmpb_rx + msize)) {
		static const char marker_data[] =
			//"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
			"\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43";
		mmpi_rx = mempcpy(mmpi_rx, marker_data, 16);
	}
	mmpi_rx = mmpb_rx;
}

static void hex_dump(void *pkt, size_t length, u64 addr)
{
	const unsigned char *address = (unsigned char *)pkt;
	const unsigned char *line = address;
	size_t line_size = 32;
	unsigned char c;
	char buf[32];
	int i = 0;

	if (!DEBUG_HEXDUMP)
		return;

	sprintf(buf, "addr=%llu", addr);
	printf("length = %zu\n", length);
	printf("%s | ", buf);
	while (length-- > 0) {
		printf("%02X ", *address++);
		if (!(++i % line_size) || (length == 0 && i % line_size)) {
			if (length == 0) {
				while (i++ % line_size)
					printf("__ ");
			}
			printf(" | ");	/* right close */
			while (line < address) {
				c = *line++;
				printf("%c", (c < 33 || c == 255) ? 0x2E : c);
			}
			printf("\n");
			if (length > 0)
				printf("%s | ", buf);
		}
	}
	printf("\n");
}

static void handle_pkt(void *pkt, size_t length, u64 addr)
{
	write_to_file(pkt, length);

	unsigned long now = get_nsecs();
	long dt = now - prev_dump;
	bool sample_now = (dt / 10000000000.) >= (opt_interval * 10.);

	if (!DEBUG_HEXDUMP || !sample_now)
		return;
	prev_dump = now;

	hex_dump(pkt, length, addr);
}

static size_t gen_eth_frame(struct xsk_umem_info *umem, u64 addr)
{
	memcpy(xsk_umem__get_data(umem->buffer, addr), pkt_data,
	       sizeof(pkt_data) - 1);
	return sizeof(pkt_data) - 1;
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

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem)
{
	struct xsk_socket_config cfg;
	struct xsk_socket_info *xsk;
	int ret;
	u32 idx;
	int i;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		exit_with_error(errno);

	xsk->umem = umem;
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg.libbpf_flags = 0;
	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = opt_xdp_bind_flags;
	ret = xsk_socket__create(&xsk->xsk, opt_if, opt_queue, umem->umem,
				 &xsk->rx, &xsk->tx, &cfg);
	if (ret)
		exit_with_error(-ret);

	ret = bpf_get_link_xdp_id(opt_ifindex, &prog_id, opt_xdp_flags);
	if (ret)
		exit_with_error(-ret);

	ret = xsk_ring_prod__reserve(&xsk->umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS,
				     &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		exit_with_error(-ret);
	for (i = 0;
	     i < XSK_RING_PROD__DEFAULT_NUM_DESCS *
		     XSK_UMEM__DEFAULT_FRAME_SIZE;
	     i += XSK_UMEM__DEFAULT_FRAME_SIZE)
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) = i;
	xsk_ring_prod__submit(&xsk->umem->fq,
			      XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk;
}

static struct option long_options[] = {
	{"rxdrop", no_argument, 0, 'r'},
	{"txonly", no_argument, 0, 't'},
	{"rxtx", no_argument, 0, 'b'},
	{"interface", required_argument, 0, 'i'},
	{"queue", required_argument, 0, 'q'},
	{"poll", no_argument, 0, 'p'},
	{"xdp-skb", no_argument, 0, 'S'},
	{"xdp-native", no_argument, 0, 'N'},
	{"interval", required_argument, 0, 'n'},
	{"zero-copy", no_argument, 0, 'z'},
	{"copy", no_argument, 0, 'c'},
	{0, 0, 0, 0}
};

static void usage(const char *prog)
{
	const char *str =
		"  Usage: %s [OPTIONS]\n"
		"  Options:\n"
		"  -r, --rxdrop		Discard all incoming packets (default)\n"
		"  -t, --txonly		Only send packets\n"
		"  -b, --rxtx		Discard all incoming packets and send packets\n"
		"  -i, --interface=n	Run on interface n\n"
		"  -q, --queue=n	Use queue n (default 0)\n"
		"  -p, --poll		Use poll syscall\n"
		"  -S, --xdp-skb=n	Use XDP skb-mod\n"
		"  -N, --xdp-native=n	Enfore XDP native mode\n"
		"  -n, --interval=n	Specify statistics update interval (default 1 sec).\n"
		"  -d, --duration=n	Specify run duration (default 10 sec).\n"
		"  -h, --host=n		Host side n={A,B} for packet header.\n"
		"  -z, --zero-copy      Force zero-copy mode.\n"
		"  -c, --copy           Force copy mode.\n"
		"\n";
	fprintf(stderr, str, prog);
	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
	int option_index, c;

	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv, "Frtbi:q:psSNn:d:h:cz", long_options,
				&option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'r':
			opt_bench = BENCH_RXDROP;
			break;
		case 't':
			opt_bench = BENCH_TXONLY;
			break;
		case 'b':
			opt_bench = BENCH_RXTX;
			break;
		case 'i':
			opt_if = optarg;
			break;
		case 'q':
			opt_queue = atoi(optarg);
			break;
		case 'p':
			opt_poll = 1;
			break;
		case 'S':
			opt_xdp_flags |= XDP_FLAGS_SKB_MODE;
			opt_xdp_bind_flags |= XDP_COPY;
			break;
		case 'N':
			opt_xdp_flags |= XDP_FLAGS_DRV_MODE;
			break;
		case 'n':
			opt_interval = atoi(optarg);
			break;
		case 'd':
			opt_duration = atoi(optarg);
			break;
		case 'h':
			opt_host = strncmp(optarg, "A", 1);
			break;
		case 'z':
			opt_xdp_bind_flags |= XDP_ZEROCOPY;
			break;
		case 'c':
			opt_xdp_bind_flags |= XDP_COPY;
			break;
		case 'F':
			opt_xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		default:
			usage(basename(argv[0]));
		}
	}

	opt_ifindex = if_nametoindex(opt_if);
	if (!opt_ifindex) {
		fprintf(stderr, "ERROR: interface \"%s\" does not exist\n",
			opt_if);
		usage(basename(argv[0]));
	}

}

static void kick_tx(struct xsk_socket_info *xsk)
{
	int ret;

	ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY)
		return;
	exit_with_error(errno);
}

static inline void complete_tx_only(struct xsk_socket_info *xsk)
{
	unsigned int rcvd;
	u32 idx;

	if (!xsk->outstanding_tx)
		return;

	kick_tx(xsk);

	rcvd = xsk_ring_cons__peek(&xsk->umem->cq, BATCH_SIZE, &idx);
	if (rcvd > 0) {
		xsk_ring_cons__release(&xsk->umem->cq, rcvd);
		xsk->outstanding_tx -= rcvd;
		xsk->tx_npkts += rcvd;
		global_tx_npkts += rcvd;
	}
}

static void rx_drop(struct xsk_socket_info *xsk)
{
	unsigned int rcvd, i;
	u32 idx_rx = 0, idx_fq = 0;
	int ret;
	int ignored = 0;

	rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	while (ret != rcvd) {
		if (ret < 0)
			exit_with_error(-ret);
		ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	}

	for (i = 0; i < rcvd; i++) {
		u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
		char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

		// Simple sanity checks, before handling the packet
		// const char *check = (char *)(pkt + 18); strncmp(check, "\x00\x00\x00\x00", 4)
		const char *check = (char *)(pkt + 40);
		int eq = 1;
		eq = strncmp(check, "\x6d\xa3", 2);
		if (eq == 0) {
			handle_pkt(pkt, len, addr);
		} else {
			hex_dump(pkt, len, addr);
			fprintf(stdout, "INFO: checksum check failed: %d\n", eq);
			ignored += 1;
		}
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = addr;
	}

	xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
	xsk_ring_cons__release(&xsk->rx, rcvd);
	xsk->rx_npkts += (rcvd - ignored);
}

static void rx_drop_all(void)
{
	struct pollfd fds[MAX_SOCKS + 1];
	int i, ret, timeout, nfds = 1;

	memset(fds, 0, sizeof(fds));

	for (i = 0; i < num_socks; i++) {
		fds[i].fd = xsk_socket__fd(xsks[i]->xsk);
		fds[i].events = POLLIN;
		timeout = 1000; /* 1sn */
	}

	for (;;) {
		if (opt_poll) {
			ret = poll(fds, nfds, timeout);
			if (ret <= 0)
				continue;
		}

		for (i = 0; i < num_socks; i++)
			rx_drop(xsks[i]);
	}
}

static void rate_limit_tx(void)
{
	int tx_pps;
	long sleep_ns;

	unsigned long now = get_nsecs();
	long dt = now - prev_rate_check;

	long d_npkts = global_tx_npkts - prev_global_tx_npkts;

	tx_pps = d_npkts * 1000000000. / dt;

	if (tx_pps > RATE_LIMIT) {
		sleep_ns = (d_npkts * 1000000000. / RATE_LIMIT) - dt;

		/*int retry;
		struct timespec ts;
		struct timespec rem;
		ts.tv_sec = 0;
		ts.tv_nsec = sleep_ns;
		retry = nanosleep(&ts, &rem);
		while (retry) {
			ts = rem;
			retry = nanosleep(&ts, &rem);
		}*/

		// Busy wait implementation
		while (now < prev_rate_check + sleep_ns) {
			now = get_nsecs();
		}
	}

	prev_rate_check = now;
	prev_global_tx_npkts = global_tx_npkts;
}

static void tx_only(struct xsk_socket_info *xsk)
{
	int timeout, ret, nfds = 1;
	struct pollfd fds[nfds + 1];
	u32 idx, frame_nb = 0;
	u64 addr;

	memset(fds, 0, sizeof(fds));
	fds[0].fd = xsk_socket__fd(xsk->xsk);
	fds[0].events = POLLOUT;
	timeout = 1000; /* 1sn */

	//
	size_t outlen = ETHER_SIZE - l4_header_size - 1;
	//

	for (;;) {
		if (opt_poll) {
			ret = poll(fds, nfds, timeout);
			if (ret <= 0)
				continue;

			if (!(fds[0].revents & POLLOUT))
				continue;
		}

		if (xsk_ring_prod__reserve(&xsk->tx, BATCH_SIZE, &idx) ==
		    BATCH_SIZE) {
			unsigned int i;

			for (i = 0; i < BATCH_SIZE; i++) {
				addr = (frame_nb + i) << XSK_UMEM__DEFAULT_FRAME_SHIFT;

				if ((mmpi_tx + outlen) >= (mmpb_tx + msize)) {
					mmpi_tx = mmpb_tx;
				}

				memcpy(xsk_umem__get_data(xsk->umem->buffer, addr) + l4_header_size, mmpi_tx,
					sizeof(pkt_data) - 1 - l4_header_size);

				mmpi_tx = mmpi_tx + outlen;

				xsk_ring_prod__tx_desc(&xsk->tx, idx + i)->addr = addr;
				xsk_ring_prod__tx_desc(&xsk->tx, idx + i)->len =
					sizeof(pkt_data) - 1;
			}

			xsk_ring_prod__submit(&xsk->tx, BATCH_SIZE);
			xsk->outstanding_tx += BATCH_SIZE;
			frame_nb += BATCH_SIZE;
			frame_nb %= NUM_FRAMES;
		}

		complete_tx_only(xsk);
		if (prev_global_tx_npkts + RATE_LIMIT_CHECK < global_tx_npkts)
			rate_limit_tx();
	}
}

static void set_affinity(int cpu_id)
{
	int res = 0;
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(cpu_id, &mask);
	CPU_SET(cpu_id + 2, &mask);
	res = sched_setaffinity(0, sizeof(mask), &mask);
	fprintf(stdout, "INFO: %d Affinity set to: %d and %d\n", res, cpu_id, cpu_id + 1);
}

static void *rx_p(void *arg)
{
	(void)arg;
	fprintf(stdout, "INFO: Started rx_p\n");
	rx_drop_all();

	return NULL;
}

static void *tx_p(void *arg)
{
	(void)arg;
	fprintf(stdout, "INFO: Started tx_p\n");
	tx_only(xsks[0]);

	return NULL;
}

static void rxtx(void)
{
	int ret, attr_setup;
	cpu_set_t mask;
	pthread_attr_t attr1, attr2;
	pthread_t pt1, pt2;

	CPU_ZERO(&mask);
	CPU_SET(18, &mask);
	attr_setup = pthread_attr_init(&attr1);
	pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &mask);
	ret = pthread_create(&pt1, &attr1, rx_p, NULL);
	fprintf(stdout, "INFO: rx_p returned %d, attr_setup %d\n", ret, attr_setup);

	CPU_ZERO(&mask);
	CPU_SET(20, &mask);
	attr_setup = pthread_attr_init(&attr2);
	pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &mask);
	ret = pthread_create(&pt2, &attr2, tx_p, NULL);
	fprintf(stdout, "INFO: tx_p returned %d, attr_setup %d\n", ret, attr_setup);

	for (;;) {
		sleep(opt_interval);
	}
}

int main(int argc, char **argv)
{
	int chd;
	chd = chdir("/tmp");
	fprintf(stdout, "INFO: chdir res: %d\n", chd);
	//
	set_affinity(18);

	// Open mmaped receive file
        fh_rx = open("/tmp/test_local.rx", O_RDWR);
	mmpb_rx = mmap(NULL, msize, PROT_WRITE, MAP_SHARED, fh_rx, 0);
	if (mmpb_rx == MAP_FAILED)
		fprintf(stdout, "ERR: memory mapping failed\n");
	mmpi_rx = mmpb_rx;
	close(fh_rx);

	// Open mmaped send file
        fh_tx = open("/tmp/test_local.tx", O_RDWR);
	mmpb_tx = mmap(NULL, msize, PROT_WRITE, MAP_SHARED, fh_rx, 0);
	if (mmpb_tx == MAP_FAILED)
		fprintf(stdout, "ERR: memory mapping failed\n");
	mmpi_tx = mmpb_tx;
	close(fh_tx);

	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct xsk_umem_info *umem;
	pthread_t pt;
	void *bufs;
	int ret;

	parse_command_line(argc, argv);


	memset(pkt_data, 65, ETHER_SIZE * sizeof(char));
	if (opt_host == HOST_A) {
		memcpy(pkt_data, header_A, sizeof(header_A) - 1);
	} else {
		memcpy(pkt_data, header_B, sizeof(header_B) - 1);
	}
	
	hex_dump(pkt_data, sizeof(pkt_data), 0);

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	ret = posix_memalign(&bufs, getpagesize(), /* PAGE_SIZE aligned */
			     NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
	if (ret)
		exit_with_error(ret);

       /* Create sockets... */
	umem = xsk_configure_umem(bufs,
				  NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
	xsks[num_socks++] = xsk_configure_socket(umem);

	if (opt_bench == BENCH_TXONLY || opt_bench == BENCH_RXTX) {
		int i;

		// Spray the umem with sample packets, header included
		for (i = 0; i < NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE;
		     i += XSK_UMEM__DEFAULT_FRAME_SIZE)
			(void)gen_eth_frame(umem, i);
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

	setlocale(LC_ALL, "");

	preheat_mem();

	ret = pthread_create(&pt, NULL, poller, NULL);
	if (ret)
		exit_with_error(ret);

	prev_time = get_nsecs();
	prev_dump = get_nsecs();

	if (opt_bench == BENCH_RXDROP)
		rx_drop_all();
	else if (opt_bench == BENCH_TXONLY)
		tx_only(xsks[0]);
	else if (opt_bench == BENCH_RXTX) {
		fprintf(stdout, "INFO: started %d\n", opt_bench);
		rxtx();
	} else {
		fprintf(stderr, "ERR: unknown benchmark %d\n", opt_bench);
	}

	return 0;
}
