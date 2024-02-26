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

struct bpf_map_def SEC("maps") num_xsks = {
		.type        = BPF_MAP_TYPE_ARRAY,
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(__u32),
		.max_entries = 1,
};

struct bpf_map_def SEC("maps") local_addr = {
		.type        = BPF_MAP_TYPE_ARRAY,
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(struct hercules_app_addr),
		.max_entries = 1,
};

static int redirect_count = 0;
static __u32 zero = 0;

SEC("xdp")
int xdp_prog_redirect_userspace(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	size_t min_len = sizeof(struct ether_header) +
	                sizeof(struct iphdr) +
	                sizeof(struct udphdr) +
	                sizeof(struct scionhdr) +
	                sizeof(struct scionaddrhdr_ipv4) +
	                sizeof(struct udphdr);
	if(data + min_len > data_end) {
		return XDP_PASS; // too short
	}
	const struct ether_header *eh = (const struct ether_header *)data;
	if(eh->ether_type != htons(ETHERTYPE_IP)) {
		return XDP_PASS; // not IP
	}
	const struct iphdr *iph = (const struct iphdr *)(eh + 1);
	if(iph->protocol != IPPROTO_UDP) {
		return XDP_PASS; // not UDP
	}

	// get listening address
	struct hercules_app_addr *addr = bpf_map_lookup_elem(&local_addr, &zero);
	if(addr == NULL) {
		return XDP_PASS; // not listening
	}

	// check if IP address matches
	if(iph->daddr != addr->ip) {
		return XDP_PASS; // not addressed to us (IP address)
	}

	// check if UDP port matches
	const struct udphdr *udph = (const struct udphdr *)(iph + 1);
	if(udph->uh_dport != htons(SCION_ENDHOST_PORT)) {
		return XDP_PASS; // not addressed to us (UDP port)
	}

	// parse SCION header
	const struct scionhdr *scionh = (const struct scionhdr *)(udph + 1);
	if(scionh->version != 0u) {
		return XDP_PASS; // unsupported SCION version
	}
	if(scionh->dst_type != 0u) {
		return XDP_PASS; // unsupported destination address type
	}
	if(scionh->src_type != 0u) {
		return XDP_PASS; // unsupported source address type
	}
	__u8 next_header = scionh->next_header;
	size_t next_offset = sizeof(struct ether_header) +
	                     sizeof(struct iphdr) +
	                     sizeof(struct udphdr) +
	                     scionh->header_len * SCION_HEADER_LINELEN;
	if(next_header == SCION_HEADER_HBH) {
		if(data + next_offset + 2 > data_end) {
			return XDP_PASS;
		}
		next_header = *((__u8 *)data + next_offset);
		next_offset += (*((__u8 *)data + next_offset + 1) + 1) * SCION_HEADER_LINELEN;
	}
	if(next_header == SCION_HEADER_E2E) {
		if(data + next_offset + 2 > data_end) {
			return XDP_PASS;
		}
		next_header = *((__u8 *)data + next_offset);
		next_offset += (*((__u8 *)data + next_offset + 1) + 1) * SCION_HEADER_LINELEN;
	}
	if(next_header != IPPROTO_UDP) {
		return XDP_PASS;
	}

	const struct scionaddrhdr_ipv4 *scionaddrh = (const struct scionaddrhdr_ipv4 *)(scionh + 1);
	if(scionaddrh->dst_ia != addr->ia) {
		return XDP_PASS; // not addressed to us (IA)
	}
	if(scionaddrh->dst_ip != addr->ip) {
		return XDP_PASS; // not addressed to us (IP in SCION hdr)
	}

	size_t offset = next_offset;

	// Finally parse the L4-UDP header
	const struct udphdr *l4udph = (struct udphdr *)(data + offset);
	if((void *)(l4udph + 1) > data_end) {
		return XDP_PASS; // too short after all
	}
	if(l4udph->dest != addr->port) {
		return XDP_PASS;
	}
	offset += sizeof(struct udphdr);

	// write the payload offset to the first word, so that the user space program can continue from there.
	*(__u32 *)data = offset;

	__u32 *_num_xsks = bpf_map_lookup_elem(&num_xsks, &zero);
	if(_num_xsks == NULL) {
		return XDP_PASS;
	}
	__sync_fetch_and_add(&redirect_count, 1);

	return bpf_redirect_map(&xsks_map, (redirect_count) % (*_num_xsks),
	                        0); // XXX distribute across multiple sockets, once available
}

char _license[] SEC("license") = "GPL";