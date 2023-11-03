/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Meta */

#define TASK_COMM_LEN 16
#define MAX_STACK_LEN 127

struct task_info {
	pid_t pid;
	pid_t tid;
	__u32 state;
	char comm[TASK_COMM_LEN];

	int kstack_len;

	__u64 kstack[MAX_STACK_LEN];
};
