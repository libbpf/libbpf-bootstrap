#include "vmlinux.h"
 #include <bpf/bpf_helpers.h> 
struct event {
    int pid;
    char comm[16];
    char filename[256];
};

// This defines the Ring Buffer Map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB of memory
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_openat")
int handle_tp(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    // 1. Reserve space in the ring buffer for one event
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) 
        return 0; // If buffer is full, just skip (don't crash the kernel!)

    // 2. Fill the data
    e->pid = bpf_get_current_pid_tgid() >> 32; // Get the actual PID
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    const char *user_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), user_ptr);

    // 3. Submit to the ring buffer (Python can now see it!)
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
