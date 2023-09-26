// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe")
int BPF_UPROBE(uprobe_add, int a, int b)
{
	long ip;

	ip = PT_REGS_IP(ctx);
	bpf_printk("UPROBE    IP 0x%lx.", ip);
	return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(uretprobe_add, int ret)
{
	struct task_struct *t = (void *)bpf_get_current_task();
	struct uprobe_dispatch_data *ud;
	long ip;

	ud = (void *)BPF_CORE_READ(t, utask, vaddr);
	ip = BPF_CORE_READ(ud, bp_addr);
	bpf_printk("URETPROBE IP 0x%lx.", ip);
	return 0;
}

/*
SEC("uprobe//proc/self/exe:uprobed_sub")
int BPF_UPROBE(uprobe_sub, int a, int b)
{
	bpf_printk("uprobed_sub ENTRY: a = %d, b = %d", a, b);
	return 0;
}

SEC("uretprobe//proc/self/exe:uprobed_sub")
int BPF_URETPROBE(uretprobe_sub, int ret)
{
	bpf_printk("uprobed_sub EXIT: return = %d", ret);
	return 0;
}
*/
