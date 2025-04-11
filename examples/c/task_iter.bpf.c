// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Meta */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "task_iter.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct task_info);
} task_info_buf SEC(".maps");

struct task_struct___post514 {
	unsigned int __state;
} __attribute__((preserve_access_index));

struct task_struct___pre514 {
	long state;
} __attribute__((preserve_access_index));

static __u32 get_task_state(void *arg)
{
	if (bpf_core_field_exists(struct task_struct___pre514, state)) {
		struct task_struct___pre514 *task = arg;

		return task->state;
	} else {
		struct task_struct___post514 *task = arg;

		return task->__state;
	}
}

static __u32 zero = 0;

SEC("iter/task")
int get_tasks(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_info *t;
	long res;

	if (!task)
		return 0;

	t = bpf_map_lookup_elem(&task_info_buf, &zero);
	if (!t)
		return 0;

	t->pid = task->tgid;
	t->tid = task->pid;
	t->state = get_task_state(task);

	bpf_probe_read_kernel_str(t->comm, TASK_COMM_LEN, task->comm);

	res = bpf_get_task_stack(task, t->kstack, sizeof(__u64) * MAX_STACK_LEN, 0);
	t->kstack_len = res <= 0 ? res : res / sizeof(t->kstack[0]);

	bpf_seq_write(seq, t, sizeof(struct task_info));
	return 0;
}
