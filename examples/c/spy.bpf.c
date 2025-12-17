#include "vmlinux.h"
 #include <bpf/bpf_helpers.h> 
SEC("tracepoint/syscalls/sys_enter_openat")
 int handle_openat(struct trace_event_raw_sys_enter *ctx) { 
/* ctx->args[] holds the arguments for the system call.
 For openat, the arguments are:
 0: dfd
 1: filename (This is what we want!)
 2: flags 3: mode */
 char filename[256];
 // Step 1: Get the pointer to the filename from the arguments 
const char *user_ptr = (const char *)ctx->args[1];
 // Step 2: Safely copy the string from user space to our variable 
// If we don't do this, the verifier will reject the code.
 bpf_probe_read_user_str(filename, sizeof(filename), user_ptr); 
// Step 3: Print it to the trace pipe so we can see it
 bpf_printk("Spy detected openat: %s\n", filename); return 0; 
} 
char LICENSE[] SEC("license") = "Dual BSD/GPL";
