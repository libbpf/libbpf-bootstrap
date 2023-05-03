/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Meta Platforms, Inc. */
#ifndef __PROFILE_H_
#define __PROFILE_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH         128
#endif

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

/* This function is from libbpf, but it is not a public API and can only be
used for demonstration, because we statically link against the libbpf
submodule during build */
extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

struct stacktrace_event {
	__u32 pid;
	__u32 cpu_id;
	char comm[TASK_COMM_LEN];
	__s32 kstack_sz;
	__s32 ustack_sz;
	stack_trace_t kstack;
	stack_trace_t ustack;
};

#endif /* __PROFILE_H_ */
