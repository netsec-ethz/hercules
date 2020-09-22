// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2017 - 2018 Intel Corporation.
// Copyright(c) 2019 ETH Zurich.

#include <linux/bpf.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stddef.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"

#include <bpf/bpf_helpers.h>

#pragma GCC diagnostic pop

struct bpf_map_def SEC("maps") xsks_map = {
		.type        = BPF_MAP_TYPE_XSKMAP,
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(__u32),
		.max_entries = 256,
};

struct bpf_map_def SEC("maps") local_addrs = {
		.type        = BPF_MAP_TYPE_ARRAY,
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(__u32),
		.max_entries = 256,
};

SEC("xdp")
int xdp_prog_redirect_userspace(struct xdp_md *ctx)
{
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	if(data + sizeof(struct ether_header) + sizeof(struct iphdr) > data_end) {
		return XDP_PASS; // too short
	}
	const struct ether_header *eh = (const struct ether_header *) data;
	if(eh->ether_type != htons(ETHERTYPE_IP)) {
		return XDP_PASS; // not IP
	}
	const struct iphdr *iph = (const struct iphdr *) (data + sizeof(struct ether_header));
	if(iph->protocol != IPPROTO_UDP) {
		return XDP_PASS; // not UDP
	}
	// TODO XXX HACKY: for now we only check the overlay IP (this can still lead to traffic loss at this destination host)
	//__u32 idx = 0;
	//__u32 *ip = bpf_map_lookup_elem(&local_addrs, &idx);
	//if(ip == NULL || iph->daddr != *ip) {
	//	return XDP_PASS; // overlay not addressed to us
	//}
	// TODO check if IP address matches (loop)
	// or just check l4 port for now??
	// should be enough for GTS experiments
	// however, this will be needed before production anyways
	// TODO check udp port == SCION_ENDHOST_PORT
	// TODO check scion header (ver_dst_src == IPv4)
	// TODO check scion header (dst IA)
	// TODO check scion header (dst IP from above)
	// TODO check scion header (next_header == UDP)
	// TODO check L4UDP port (based on IP from above)
	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
}

char _license[] SEC("license") = "GPL";