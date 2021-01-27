// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2017 - 2018 Intel Corporation.
// Copyright(c) 2019 ETH Zurich.

#include <linux/bpf.h>
#include <bpf/src/bpf_helpers.h>

SEC("xdp")
int xdp_prog_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";