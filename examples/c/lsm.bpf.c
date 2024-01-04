#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM  1

SEC("lsm/bpf")
int BPF_PROG(lsm_bpf, int cmd, union bpf_attr *attr, unsigned int size, int ret)
{
    /* ret is the return value from the previous BPF program
     * or 0 if it's the first hook.
     */
    if (ret != 0)
        return ret;

    bpf_printk("LSM: block bpf() worked");
    return -EPERM;
}
