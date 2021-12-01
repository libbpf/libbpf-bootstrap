#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define	EPERM		 1

char value[32];
unsigned int pid_namespace;

static bool isequal(const char *a, const char *b){
  #pragma unroll
  for (int i = 0; i < 32; i++){
    if (a[i] == '\0' && b[i] == '\0')
      break;

    if(a[i] != b[i])
      return false;
  }
  return true;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_stuff, struct linux_binprm *bprm, int ret) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  struct ns_common pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns);
  if (pid_namespace != pid_ns.inum){
    bpf_printk("%d %d", pid_namespace, pid_ns.inum);
    return ret;
  }
  bpf_printk("exec in the container");
  if (ret != 0)
    return ret;
  char filename[32]  ;

  bpf_probe_read_str(&filename, 32, bprm->filename);
    bool comp = isequal(filename, value);
    if (comp)
      return -EPERM;

  return ret;
}

