#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

SEC("ksyscall/kill")
int BPF_KSYSCALL(entry_probe, pid_t tpid, int sig) {

  char comm[TASK_COMM_LEN];

  if (sig == 0) {
    /**
        If sig is 0, then no signal is sent, but existence and permission
        checks are still performed; this can be used to check for the
        existence of a process ID or process group ID that the caller is
        permitted to signal.
    */
    return 0;
  }


  if (bpf_get_current_comm(&comm, sizeof(comm)) == 0) {
    
    char fmt[] = "KILL syscall called on %d (%s) with signal: %d.";
    bpf_trace_printk(fmt, sizeof(fmt), tpid, comm, sig);
  }
  return 0;
}

char _license[] SEC("license") = "GPL";