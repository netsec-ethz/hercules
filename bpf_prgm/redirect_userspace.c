// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2017 - 2018 Intel Corporation.
// Copyright(c) 2019 ETH Zurich.

#include <linux/bpf.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stddef.h>
#include "packet.h"
#include "hercules.h"

#include <bpf/src/bpf_helpers.h>


struct bpf_map_def SEC("maps") xsks_map = {
		.type        = BPF_MAP_TYPE_XSKMAP,
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(__u32),
		.max_entries = MAX_NUM_SOCKETS,
};

struct bpf_map_def SEC("maps") local_addr = {
		.type        = BPF_MAP_TYPE_HASH,
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(struct hercules_app_addr),
		.max_entries = 1,
};

SEC("xdp")
int xdp_prog_redirect_userspace(struct xdp_md *ctx)
{
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	size_t offset = sizeof(struct ether_header) +
					sizeof(struct iphdr) +
					sizeof(struct udphdr) +
					sizeof(struct scionhdr) +
					sizeof(struct scionaddrhdr_ipv4) +
					sizeof(struct udphdr);
	if(data + offset > data_end) {
		return XDP_PASS; // too short
	}
	const struct ether_header *eh = (const struct ether_header *) data;
	if(eh->ether_type != htons(ETHERTYPE_IP)) {
		return XDP_PASS; // not IP
	}
	const struct iphdr *iph = (const struct iphdr *) (eh + 1);
	if(iph->protocol != IPPROTO_UDP) {
		return XDP_PASS; // not UDP
	}

	// get listening address
	__u32 zero = 0;
	struct hercules_app_addr *addr = bpf_map_lookup_elem(&local_addr, &zero);
	if(addr == NULL) {
		return XDP_PASS; // not listening
	}

	// check if IP address matches
	if(iph->daddr != addr->ip) {
		return XDP_PASS; // not addressed to us (IP address)
	}

	// check if UDP port matches
	const struct udphdr *udph = (const struct udphdr *) (iph + 1);
	if(udph->uh_dport != htons(SCION_ENDHOST_PORT)) {
		return XDP_PASS; // not addressed to us (UDP port)
	}

	// parse SCION header
	const struct scionhdr *scionh = (const struct scionhdr *) (udph + 1);
	const __u16 expected_ver_dst_src = htons(0 << 12 | 1 << 6 | 1 << 0); // version: 0, dst, src: 1 (IPv4)
	if(scionh->ver_dst_src != expected_ver_dst_src) {
		return XDP_PASS;
	}
	if(scionh->next_header != IPPROTO_UDP) {
		return XDP_PASS;
	}

	const struct scionaddrhdr_ipv4 *scionaddrh = (const struct scionaddrhdr_ipv4 *) (scionh + 1);
	if(scionaddrh->dst_ia != addr->ia) {
		return XDP_PASS; // not addressed to us (IA)
	}
	if(scionaddrh->dst_ip != addr->ip) {
		return XDP_PASS; // not addressed to us (IP in SCION hdr)
	}
	offset += scionh->header_len * 8 - // Header length is in lineLen of 8 bytes
								  sizeof(struct scionhdr) -
								  sizeof(struct scionaddrhdr_ipv4);

	// Finally parse the L4-UDP header
	const struct udphdr *l4udph = ((void *) scionh) + scionh->header_len * 8;
	if((void *) (l4udph + 1) > data_end) {
		return XDP_PASS; // too short after all
	}
	if(l4udph->dest != addr->port) {
		return XDP_PASS;
	}

	// write the payload offset to the first word, so that the user space program can continue from there.
	*(__u32 *) data = offset;
	return bpf_redirect_map(&xsks_map, 0, 0); // XXX distribute across multiple sockets, once available
}

char _license[] SEC("license") = "GPL";