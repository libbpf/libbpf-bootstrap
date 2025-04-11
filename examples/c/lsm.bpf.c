#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static bool isequal(const char *a, const char *b) {
#pragma unroll
  for (int i = 0; i < 32; i++) {
    if (a[i] == '\0' || b[i] == '\0')
      break;

    if (a[i] != b[i])
      return false;
  }
  return true;
}

static bool in_pid_ns(unsigned int pid_namespace, struct task_struct *t) {

  struct ns_common pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns);
  if (pid_namespace != pid_ns.inum) {
    return false;
  }
  return true;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define	EPERM		 1

char value[32];
unsigned int pid_namespace;

SEC("lsm/bprm_check_security")
int BPF_PROG(executable_block, struct linux_binprm *bprm, int ret) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  if (!in_pid_ns(pid_namespace, t))
    return ret;

  if (ret != 0)
    return ret;
  char filename[32];

  bpf_probe_read_str(&filename, 32, bprm->filename);
  bpf_printk("%s", filename);
  bool comp = isequal(filename, value);
  if (comp)
    return -EPERM;

  return ret;

}
