// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "snooper.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct task_state {
	struct task_event event;
	struct bpf_task_work tw;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct task_state);
} task_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} rb SEC(".maps");

/*
 * Frame pointer-based user stack unwinding.
 *
 * On x86_64 with frame pointers enabled (-fno-omit-frame-pointer):
 *   [rbp + 0]  = saved rbp (previous frame pointer)
 *   [rbp + 8]  = return address
 *
 * We walk the chain of frame pointers to collect return addresses.
 */
static int unwind_user_stack(struct task_struct *task, __u64 *stack, int max_depth)
{
	struct pt_regs *regs;
	struct frame {
		__u64 next_fp;    /* saved frame pointer (rbp) */
		__u64 ret_addr;   /* return address */
	} frame;
	__u64 fp;
	unsigned i = 0;

	regs = bpf_core_cast((void *)bpf_task_pt_regs(task), struct pt_regs);
	if (!(regs->cs & 3))
		return 0; /* not in user space mode */

	stack[0] = regs->ip;

	fp = regs->bp;
	bpf_for(i, 1, MAX_STACK_DEPTH) {
		/* read the frame, [fp] = next_fp, [fp+8] = ret_addr */
		if (bpf_copy_from_user_task(&frame, sizeof(frame), (void *)fp, task, 0))
			break;

		barrier_var(i);
		if (i < MAX_STACK_DEPTH)
			stack[i] = frame.ret_addr;

		fp = frame.next_fp;
	}

	return i * sizeof(__u64);
}

static int task_work_cb(struct bpf_map *map, void *key, void *value)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct task_state *state = value;
	struct task_event *event = &state->event;
	__u32 tid = task->pid;

	if (event->tid != task->pid) {
		bpf_printk("MISMATCHED PID %d != expected %d", task->pid, event->tid);
		goto cleanup;
	}

	event->ustack_sz = unwind_user_stack(task, event->ustack, MAX_STACK_DEPTH);

	bpf_ringbuf_output(&rb, event, sizeof(*event), 0);

cleanup:
	bpf_map_delete_elem(&task_states, key);
	return 0;
}

/*
 * THIS DOESN'T CURRENTLY WORK:
 * static struct task_state empty_state;
 *
 * Verifier will complain:
 * bpf_task_work cannot be accessed directly by load/store
 */
static char empty_state[sizeof(struct task_state)];

SEC("iter.s/task")
int snoop_tasks(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_state *state;
	struct task_event *event;
	__u32 tid;
	int err;

	if (!task)
		return 0;

	tid = task->pid;

	err = bpf_map_update_elem(&task_states, &tid, &empty_state, BPF_NOEXIST);
	if (err) {
		bpf_printk("Unexpected error adding task state for %d (%s): %d", tid, task->comm, err);
		return 0;
	}
	state = bpf_map_lookup_elem(&task_states, &tid);
	if (!state) {
		bpf_printk("Unexpected error fetching task state for %d (%s): %d", tid, task->comm, err);
		return 0;
	}

	event = &state->event;
	event->pid = task->tgid;
	event->tid = task->pid;
	bpf_probe_read_kernel_str(event->comm, TASK_COMM_LEN, task->comm);

	event->kstack_sz = bpf_get_task_stack(task, event->kstack, sizeof(event->kstack), 0);

	err = bpf_task_work_schedule_signal_impl(task, &state->tw, &task_states, task_work_cb, NULL);
	if (err) {
		bpf_printk("Unexpected error scheduling task work %d (%s): %d", tid, task->comm, err);
		bpf_map_delete_elem(&task_states, &tid);
		return 0;
	}

	return 0;
}
