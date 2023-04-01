#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

SEC("ksyscall/tgkill")
int BPF_KSYSCALL(tgkill_entry, pid_t tgid, pid_t tid, int sig) 
{
	char comm[TASK_COMM_LEN];
	__u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

	if (sig == 0) {
		/*
			If sig is 0, then no signal is sent, but existence and permission
			checks are still performed; this can be used to check for the
			existence of a process ID or process group ID that the caller is
			permitted to signal.
		*/
		return 0;
	}

	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk("tgkill syscall called by PID %d (%s) for thread id %d with pid %d and signal %d.",
		   caller_pid, comm, tid, tgid, sig);
	return 0;
}

SEC("ksyscall/kill")
int BPF_KSYSCALL(entry_probe, pid_t pid, int sig) 
{
	char comm[TASK_COMM_LEN];
	__u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

	if (sig == 0) {
		/*
			If sig is 0, then no signal is sent, but existence and permission
			checks are still performed; this can be used to check for the
			existence of a process ID or process group ID that the caller is
			permitted to signal.
		*/
		return 0;
	}

	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk("KILL syscall called by PID %d (%s) for PID %d with signal %d.",
		   caller_pid, comm, pid, sig);
	return 0;
}

char _license[] SEC("license") = "GPL";
