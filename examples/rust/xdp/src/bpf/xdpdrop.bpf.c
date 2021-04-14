#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop(struct xdp_md *ctx)
{
	return XDP_DROP;
}

char __license[] SEC("license") = "GPL";
