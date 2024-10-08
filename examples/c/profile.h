/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Meta Platforms, Inc. */
#ifndef __PROFILE_H_
#define __PROFILE_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

#define MAX_THREAD_CNT 4096

#define RINGBUF_SZ (4 * 1024 * 1024)

enum task_status {
	STATUS_ON_CPU,
	STATUS_OFF_CPU,
};

enum event_kind {
	EV_ON_CPU,
	EV_OFF_CPU,
	EV_TIMER,
};

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct wprof_event {
	enum event_kind kind;
	__u32 cpu_id;
	__u64 ts;
	__u32 pid;
	__u32 tgid;
	char comm[TASK_COMM_LEN];

	__u64 duration_ns;

	__s32 kstack_sz;
	__s32 ustack_sz;
	stack_trace_t kstack;
	stack_trace_t ustack;
};

#endif /* __PROFILE_H_ */
