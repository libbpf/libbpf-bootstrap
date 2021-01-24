// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/bprm_execve")
int BPF_PROG(bprm_execve, struct linux_binprm *bprm, int fd, struct filename *filename, int flags)
{
	const char *name = filename->name;
	pid_t pid;

	pid = bpf_get_current_pid_tgid();

	bpf_printk("fentry: pid = %d, filename = %s\n", pid, name);
	return 0;
}

SEC("fexit/bprm_execve")
int BPF_PROG(bprm_execve_exit,
	     struct linux_binprm *bprm, int fd, struct filename *filename, int flags, int ret)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid();

	bpf_printk("fexit: pid = %d, filename = %s, ret = %d\n", pid, filename->name, ret);
	return 0;
}
