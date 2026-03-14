// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinuxcifs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "smbslower.h"

#define MAX_ENTRIES 8192

const volatile pid_t target_pid = 0;
const volatile __u32 target_cid = 0;
const volatile __u64 min_lat_ns = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct mid_q_entry *);
	__type(value, struct data);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static inline int system_endianness()
{
	int n = 1;
	// 0 for little endian, 1 for big endian
	return (*(char *)&n == 1) ? 0 : 1;
}

static inline u16 le_to_sys16(u16 x)
{
	// check system's endianness
	if (system_endianness() == 0) {
		return x;
	}
	// big endian
	return ((x >> 8) & 0xff) | // Move byte 1 to byte 0
	       ((x << 8) & 0xff00); // Move byte 0 to byte 1
}

static inline u32 le_to_sys32(u32 x)
{
	if (system_endianness() == 0) {
		return x;
	}
	// big endian
	return ((x >> 24) & 0xff) | ((x << 8) & 0xff0000) | ((x >> 8) & 0xff00) |
	       ((x << 24) & 0xff000000);
}

static inline u64 le_to_sys64(u64 x)
{
	if (system_endianness() == 0) {
		return x;
	}
	// big endian
	return ((x >> 56) & 0xff) | ((x << 40) & 0xff000000000000) | ((x << 24) & 0xff0000000000) |
	       ((x << 8) & 0xff00000000) | ((x >> 8) & 0xff000000) | ((x >> 24) & 0xff0000) |
	       ((x >> 40) & 0xff00) | ((x << 56) & 0xff00000000000000);
}

static inline u32 sys_to_le32(u32 x)
{
	return le_to_sys32(x);
}

SEC("fexit/smb2_mid_entry_alloc")
int BPF_PROG(mid_alloc_fexit, struct smb2_hdr *shdr, struct TCP_Server_Info *server,
struct mid_q_entry *mid_struct)
{
	struct data data;
	u64 pid_tid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tid >> 32;
	u16 cid = le_to_sys16(shdr->Command);

	if (target_pid && target_pid != pid)	// filter for process id
		return 0;

	if (target_cid && target_cid != cid)	// filter for command id
		return 0;

	bpf_printk("cid %d", cid);

	data.when_alloc = bpf_ktime_get_ns();
	data.session_id = le_to_sys64(shdr->SessionId);
	data.mid = le_to_sys64(mid_struct->mid);
	data.smbcommand = cid;
	if (shdr->NextCommand)
		data.is_compounded = 1;
	else
		data.is_compounded = 0;

	if (shdr->Flags & SMB2_FLAGS_ASYNC_COMMAND) {
		data.is_async = 1;
		data.id = le_to_sys64(shdr->Id.AsyncId);
	} else {
		data.is_async = 0;
		data.id = le_to_sys32(shdr->Id.SyncId.TreeId);
	}
	bpf_get_current_comm(&data.task, sizeof(data.task));
	bpf_map_update_elem(&starts, &mid_struct, &data, BPF_ANY);

	return 0;
}

SEC("fentry/__release_mid")
int BPF_PROG(mid_release_fentry, struct TCP_Server_Info *server, struct mid_q_entry *midEntry)
{
    struct data *datap;
    struct event event = {};
    __u64 end_ns, delta_ns;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	datap = bpf_map_lookup_elem(&starts, &midEntry);
    if (!datap)
	{
		return 0;
	}

    bpf_map_delete_elem(&starts, &midEntry);

    end_ns = bpf_ktime_get_ns();
    delta_ns = end_ns - datap->when_alloc;
    if (delta_ns < min_lat_ns)		// filter for min latency
        return 0;

    event.delta_us = delta_ns / NSEC_PER_USEC;
    event.when_release_us = end_ns / NSEC_PER_USEC;
    event.pid = pid;
    event.session_id = datap->session_id;
    event.id = datap->id;
    event.mid = datap->mid;
    event.smbcommand = datap->smbcommand;
    event.is_compounded = datap->is_compounded;
    event.is_async = datap->is_async;
    bpf_get_current_comm(&event.task, sizeof(event.task));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}