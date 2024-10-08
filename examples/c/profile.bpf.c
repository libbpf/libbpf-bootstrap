// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "profile.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct task_state {
	__u64 ts;
	enum task_status status;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int); /* task_id, see task_id() */
	__type(value, struct task_state);
	__uint(max_entries, MAX_THREAD_CNT);
} states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SZ);
} rb SEC(".maps");

__u64 session_start_ts;

const volatile int cpu_id = 0;

static struct task_state empty_task_state;

static __always_inline int task_id(int pid)
{
	/* use CPU ID for identifying idle tasks */
	return pid ?: -(bpf_get_smp_processor_id() + 1);
}

static struct task_state *task_state(int pid)
{
	struct task_state *s;
	int id = task_id(pid);

	s = bpf_map_lookup_elem(&states, &id);
	if (!s) {
		bpf_map_update_elem(&states, &id, &empty_task_state, BPF_NOEXIST);
		s = bpf_map_lookup_elem(&states, &id);
	}

	return s;
}

/* don't create an entry if it's not there already */
static struct task_state *task_state_peek(int pid)
{
	int id = task_id(pid);

	return bpf_map_lookup_elem(&states, &id);
}

static void task_state_delete(int pid)
{
	int id = task_id(pid);

	bpf_map_delete_elem(&states, &id);
}

static int emit_event(enum event_kind kind, u64 now_ts, struct task_struct *p, u64 duration_ns)
{
	struct wprof_event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return -1;

	e->kind = kind;
	e->ts = now_ts;
	e->cpu_id = bpf_get_smp_processor_id();
	e->pid = p->pid;
	e->tgid = p->tgid;
	__builtin_memcpy(e->comm, p->comm, sizeof(e->comm));

	e->duration_ns = duration_ns;

	e->kstack_sz = 0;
	e->ustack_sz = 0;

	/*
	event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

	event->ustack_sz =
		bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);
	*/

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("perf_event")
int wprof_tick(void *ctx)
{
	struct task_state *scur;
	struct task_struct *cur = bpf_get_current_task_btf();
	u64 now_ts, dur_ns;

	if (!session_start_ts)
		return 0;

	if (cpu_id && bpf_get_smp_processor_id() != cpu_id)
		return 0;

	scur = task_state(cur->pid);
	if (!scur)
		return 0; /* shouldn't happen, unless we ran out of space */

	now_ts = bpf_ktime_get_ns();

	/* cur task was on-cpu since last checkpoint */
	dur_ns = now_ts - (scur->ts ?: session_start_ts);
	emit_event(EV_TIMER, now_ts, cur, dur_ns);

	scur->ts = now_ts;
	scur->status = STATUS_ON_CPU;

	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(wprof_switch,
	     bool preempt,
	     struct task_struct *prev,
	     struct task_struct *next,
	     unsigned prev_state)
{
	struct task_state *sprev, *snext;
	u64 now_ts, dur_ns;

	if (!session_start_ts)
		return 0;

	if (cpu_id && bpf_get_smp_processor_id() != cpu_id)
		return 0;

	sprev = task_state(prev->pid);
	snext = task_state(next->pid);
	if (!sprev || !snext)
		return 0;

	now_ts = bpf_ktime_get_ns();

	/* prev task was on-cpu since last checkpoint */
	dur_ns = now_ts - (sprev->ts ?: session_start_ts);
	emit_event(EV_ON_CPU, now_ts, prev, dur_ns);

	/* next task was off-cpu since last checkpoint */
	dur_ns = now_ts - (snext->ts ?: session_start_ts);
	emit_event(EV_OFF_CPU, now_ts, next, dur_ns);

	sprev->ts = now_ts;
	snext->ts = now_ts;

	return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(wprof_task_wakeup_new, struct task_struct *p)
{
	struct task_state *s;
	u64 now_ts;

	if (!session_start_ts)
		return 0;

	if (cpu_id && bpf_get_smp_processor_id() != cpu_id)
		return 0;

	s = task_state(p->pid);
	if (!s)
		return 0;

	now_ts = bpf_ktime_get_ns();
	s->ts = now_ts;
	s->status = STATUS_OFF_CPU;

	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(wprof_task_exit, struct task_struct *p)
{
	struct task_state *s;
	enum event_kind kind;
	u64 now_ts;
	int id;

	if (!session_start_ts)
		return 0;

	if (cpu_id && bpf_get_smp_processor_id() != cpu_id)
		return 0;

	s = task_state_peek(p->pid);
	if (!s)
		return 0;

	now_ts = bpf_ktime_get_ns();
	kind = s->status == STATUS_ON_CPU ? EV_ON_CPU : EV_OFF_CPU;
	emit_event(kind, now_ts, p, now_ts - s->ts);

	task_state_delete(p->pid);

	return 0;
}
