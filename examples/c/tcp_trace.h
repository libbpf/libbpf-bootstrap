/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCP_TRACE_H
#define __TCP_TRACE_H


#define TASK_COMM_LEN	16

struct event {
	char comm[TASK_COMM_LEN];
	__u64 delta_us;
	__u64 ts_us;
	__u32 tgid;
	int af;
	int size_goal;
	int wmem;
	int mss;
	int true_size;
	int rxtx;
	__u32 skb_len;
	__u32 saddr;
	__u32 daddr;
	__u16 lport;
	__u16 dport;

};


#endif /* __TCP_TRACE_H */
