// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;
const char proc[TASK_COMM_LEN];
int my_pid = 0;

SEC("tp/syscalls/sys_enter_mmap")
int handle_mmap(struct perf_mmap_event *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	pid_t ppid;
	u64 ts;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
	ppid = BPF_CORE_READ(task, real_parent, tgid);

	if (ppid != my_pid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = pid;
	e->ppid = ppid;
	e->is_mmap = true;
	e->mem_event = true;
	e->page_size = ctx->min;
	bpf_get_current_comm(&e->comm, TASK_COMM_LEN);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}


SEC("tp/syscalls/sys_enter_munmap")
int handle_munmap(struct perf_mmap_event *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	pid_t ppid;
	u64 ts;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
	ppid = BPF_CORE_READ(task, real_parent, tgid);

	if (ppid != my_pid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;


	e->is_mmap = false;
	e->mem_event = true;
	e->page_size = ctx->min;
	e->pid = pid;
	e->ppid = ppid;
	bpf_get_current_comm(&e->comm, TASK_COMM_LEN);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}