// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2017 - 2018 Intel Corporation.
// Copyright(c) 2019 ETH Zurich.

#include <linux/bpf.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stddef.h>
#include "shared_bpf.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"

#include <bpf/src/bpf_helpers.h>

#pragma GCC diagnostic pop


struct bpf_map_def SEC("maps") xsks_map = {
		.type        = BPF_MAP_TYPE_XSKMAP,
		.key_size    = sizeof(u32),
		.value_size  = sizeof(u32),
		.max_entries = MAX_NUM_QUEUES,
};

struct bpf_map_def SEC("maps") local_addrs = {
		.type        = BPF_MAP_TYPE_HASH,
		.key_size    = sizeof(u32),
		.value_size  = sizeof(u32),
		.max_entries = MAX_NUM_LOCAL_ADDRS,
};

struct bpf_map_def SEC("maps") local_ports = {
		.type        = BPF_MAP_TYPE_ARRAY,
		.key_size    = sizeof(u32),
		.value_size  = sizeof(u16),
		.max_entries = MAX_NUM_LOCAL_ADDRS,
};

struct bpf_map_def SEC("maps") local_ia = {
		.type        = BPF_MAP_TYPE_ARRAY,
		.key_size    = sizeof(u32),
		.value_size  = sizeof(u64),
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

	// check if IP address matches
	u32 *addr_idx = bpf_map_lookup_elem(&local_addrs, &iph->daddr);
	if(addr_idx == NULL) {
		return XDP_PASS; // not addressed to us (IP address)
	}

	// check if UDP port matches
	const struct udphdr *udph = (const struct udphdr *) (iph + 1);
	if(udph->uh_dport != htons(SCION_ENDHOST_PORT)) {
		return XDP_PASS; // not addressed to us (UDP port)
	}

	// parse SCION header
	const struct scionhdr *scionh = (const struct scionhdr *) (udph + 1);
	const u16 expected_ver_dst_src = htons(0 << 12 | 1 << 6 | 1 << 0); // version: 0, dst, src: 1 (IPv4)
	if(scionh->ver_dst_src != expected_ver_dst_src) {
		return XDP_PASS;
	}
	if(scionh->next_header != IPPROTO_UDP) {
		return XDP_PASS;
	}

	const struct scionaddrhdr_ipv4 *scionaddrh = (const struct scionaddrhdr_ipv4 *) (scionh + 1);
	u32 zero = 0;
	u64 *ia = bpf_map_lookup_elem(&local_ia, &zero);
	if(ia == NULL || scionaddrh->dst_ia != *ia) {
		return XDP_PASS; // not addressed to us (IA)
	}
	if(scionaddrh->dst_ip != iph->daddr) {
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
	u16 *port = bpf_map_lookup_elem(&local_ports, addr_idx);
	if(port == NULL || l4udph->dest != *port) {
		return XDP_PASS;
	}

	// write the payload offset to the first word, so that the user space program can continue from there.
	*(u32 *) data = offset;
	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
}

char _license[] SEC("license") = "GPL";