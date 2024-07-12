// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobe-stress.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct counter enter_hits[MAX_CPUS];
struct counter exit_hits[MAX_CPUS];

SEC("uprobe.multi")
int uprobe(struct pt_regs *ctx)
{
	int cpu = bpf_get_smp_processor_id();

	__sync_add_and_fetch(&enter_hits[cpu & CPU_MASK].value, 1);

	return 0;
}

SEC("uretprobe.multi")
int uretprobe(struct pt_regs *ctx)
{
	int cpu = bpf_get_smp_processor_id();

	__sync_add_and_fetch(&exit_hits[cpu & CPU_MASK].value, 1);

	return 0;
}
