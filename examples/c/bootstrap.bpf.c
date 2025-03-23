// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	u64 ts;

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = false;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task;
	struct event *e;
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;

	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	/* ignore thread exits */
	if (pid != tid)
		return 0;

	/* if we recorded start of the process, calculate lifetime duration */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &pid);

	/* if process didn't live long enough, return early */
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = true;
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* all the definitions below should come from latest vmlinux.h, we just
 * haven't updated vmlinux.h for a while in libbpf-bootstrap
 */

struct bpf_iter_num {
	long __opaque[1];
};

extern __u32 bpf_dynptr_size(const struct bpf_dynptr *p) __weak __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *p, u32 offset, void *buffer__opt, u32 buffer__szk) __weak __ksym;
extern int bpf_dynptr_from_xdp(struct xdp_md *x, u64 flags, struct bpf_dynptr *ptr__uninit) __weak __ksym;

#define BUF_SZ 128
#define min(x, y) ((x) < (y) ? (x) : (y))

struct pkt_cap_hdr {
	__u32 pkt_sz;
};

SEC("xdp")
int capture_xdp_data(struct xdp_md *ctx)
{
	char buf[BUF_SZ];
	struct bpf_dynptr pkt_dp;
	struct bpf_dynptr rb_dp;
	struct pkt_cap_hdr *r;
	u32 pkt_sz, off, chunk_sz;
	int err, i, chunk_cnt;
	void *chunk;

	bpf_dynptr_from_xdp(ctx, 0, &pkt_dp); /* shouldn't fail */
	pkt_sz = bpf_dynptr_size(&pkt_dp);

	err = bpf_ringbuf_reserve_dynptr(&rb, sizeof(struct pkt_cap_hdr) + pkt_sz, 0, &rb_dp);
	if (err) { /* failed to reserve enough space */
		bpf_printk("RINGBUF OUT OF SPACE! err = %d");
		goto err_out;
	}

	r = bpf_dynptr_data(&rb_dp, 0, sizeof(*r));
	if (!r) { /* can't happen, if no bugs */
		bpf_printk("BUG! NULL dynptr data");
		goto err_out;
	}

	/* fill out metadata header for ringbuf record */
	r->pkt_sz = pkt_sz;

	/* copy data into ringbuf up to 128 bytes at a time */
	chunk_cnt = (pkt_sz + BUF_SZ - 1) / BUF_SZ;
	bpf_for(i, 0, chunk_cnt) {
		/* unfortunately bpf_dynptr_slice requires last argument to be
		 * a fixed constant, which doesn't work well for last chunk;
		 * so for the last (incomplete) chunk, we'll do less efficient
		 * bpf_dynptr_read() into buf.
		 */
		off = BUF_SZ * i;
		chunk_sz = min(pkt_sz - off, BUF_SZ);
		if (chunk_sz == BUF_SZ) {
			chunk = bpf_dynptr_slice(&pkt_dp, off, buf, BUF_SZ);
			if (!chunk) {
				bpf_printk("BUG! NULL pkt slice pointer");
				goto err_out;
			}
		} else {
			err = bpf_dynptr_read(buf, chunk_sz, &pkt_dp, off, 0);
			if (err) {
				bpf_printk("BUG! Failed to read packet data err = %d", err);
				goto err_out;
			}
			chunk = buf;
		}

		/* here, chunk pointer points to packet data */
		err = bpf_dynptr_write(&rb_dp, sizeof(*r) + off, chunk, chunk_sz, 0);
		if (err) {
			bpf_printk("BUG! err = %d");
			goto err_out;
		}
	}

	/* now there is `struct pkt_cap_hdr` followed by raw packet bytes in
	 * a single ringbuf record
	 */
	bpf_ringbuf_submit_dynptr(&rb_dp, 0);
	return 0;

err_out:
	bpf_ringbuf_discard_dynptr(&rb_dp, 0);
	return 0;
}
