#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("lsm/file_mprotect")
int BPF_PROG(mprotect_audit, struct vm_area_struct *vma, unsigned long reqprot,
             unsigned long prot, int ret)
{
  /* ret is the return value from the previous BPF program
   * or 0 if it's the first hook.
   */
  if(ret != 0)
    return ret;

  int is_heap;

  is_heap = (vma->vm_start >= vma->vm_mm->start_brk &&
             vma->vm_end <= vma->vm_mm->brk);

  /* Return an -EPERM or write information to the perf events buffer
   * for auditing
   */
  if(is_heap)
    return -EPERM;
}
