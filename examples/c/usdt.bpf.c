// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

pid_t my_pid = 0;

SEC("usdt/libc.so.6:libc:setjmp")
int BPF_USDT(usdt_auto_attach, void *arg1, int arg2, void *arg3)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

	bpf_printk("USDT auto attach to libc:setjmp: arg1 = %lx, arg2 = %d, arg3 = %lx", arg1, arg2,
		   arg3);
	return 0;
}

SEC("usdt")
int BPF_USDT(usdt_manual_attach, void *arg1, int arg2, void *arg3)
{
	bpf_printk("USDT manual attach to libc:setjmp: arg1 = %lx, arg2 = %d, arg3 = %lx", arg1,
		   arg2, arg3);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
