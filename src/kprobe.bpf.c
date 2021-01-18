// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/bprm_execve")
int BPF_KPROBE(bprm_execve, struct linux_binprm *bprm, int fd, struct filename *filename, int flags)
{
	const char *name = BPF_CORE_READ(filename, name);
	pid_t pid;

	pid = bpf_get_current_pid_tgid();

	bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, name);
	return 0;
}

SEC("kretprobe/bprm_execve")
int BPF_KRETPROBE(bprm_execve_ret, int ret)
{
	bpf_printk("KPROBE EXIT: ret = %d\n", ret);
	return 0;
}
