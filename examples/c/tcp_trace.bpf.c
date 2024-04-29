#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
 
#define MAX_ENTRIES 64
#define AF_INET    2
#define AF_INET6   10
 
 char LICENSE[] SEC("license") = "Dual BSD/GPL";

 const volatile pid_t targ_tgid = 0;
 
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	char comm[TASK_COMM_LEN];
	int ret = 0;
	// // pull in details
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	int sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);

    if (family != AF_INET) {
        return 0;
    }
	bpf_get_current_comm(&comm, sizeof(comm));
	
	if(lport == 8080)
	{
		bpf_printk("tcp send msg comm: %s, pid: %u, lport: %u, wmem: %d, send_size: %llu\n", 
				comm, tgid, lport, sk_wmem_queued, size);
	}

	return 0;
}
 
SEC("fexit/tcp_send_mss")
int BPF_PROG(tcp_send_mss, struct sock *sk, int *size_goal, int flags, int ret)
{
	struct tcp_sock *tp = (struct tcp_sock*)sk;
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	char comm[TASK_COMM_LEN];
	// 读取 size_goal 的值
	int size = 0;
	if(size_goal)
	{
		bpf_probe_read(&size, sizeof(size), (void *)size_goal);
	}

	// // pull in details
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	int gso  = BPF_CORE_READ(tp, gso_segs);

    if (family != AF_INET) {
        return 0;
    }
	bpf_get_current_comm(&comm, sizeof(comm));
	
	if(lport == 8080)
	{
		bpf_printk("tcp_send_mss gso: %d, size_goal: %d, ret: %d\n", 
				gso, size, ret);
	}
	return 0;
}

SEC("fexit/tcp_skb_entail")
int BPF_PROG(tcp_skb_entail, struct sock *sk, struct sk_buff *skb)
{
	// // pull in details
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	int sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);
	int sk_sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
	if (family != AF_INET) {
        return 0;
    }
	
	if(lport == 8080)
	{
		bpf_printk("tcp_skb_entail wmem: %d, sndbuf: %d\n", 
				sk_wmem_queued, sk_sndbuf);
	}
	return 0;
}

SEC("fentry/tcp_push_one")
int BPF_PROG(tcp_push_one, struct sock *sk, unsigned int mss_now)
{
	// // pull in details
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	int sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);
	int sk_sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
	if (family != AF_INET) {
        return 0;
    }
	
	if(lport == 8080)
	{
		bpf_printk("tcp_push_one wmem: %d, sndbuf: %d\n", 
				sk_wmem_queued, sk_sndbuf);
	}
	return 0;
}

SEC("fentry/__tcp_push_pending_frames")
int BPF_PROG(__tcp_push_pending_frames, struct sock *sk, unsigned int cur_mss, int nonagle)
{
	// // pull in details
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	int sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);
	int sk_sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
	if (family != AF_INET) {
        return 0;
    }
	
	if(lport == 8080)
	{
		bpf_printk("tcp_push_one wmem: %d, sndbuf: %d\n", 
				sk_wmem_queued, sk_sndbuf);
	}
	return 0;
}

// SEC("fentry/tcp_mark_push")
// int BPF_PROG(tcp_mark_push, struct tcp_sock *tp, struct sk_buff *skb)
// {
// 	// // pull in details
//     char comm[TASK_COMM_LEN];
// 	unsigned int len = BPF_CORE_READ(skb,len);
// 	bpf_get_current_comm(&comm, sizeof(comm));

// 	// if(comm[0] != 'p')
// 	// {
// 	// 	return 0;
		
// 	// }
// 	bpf_printk("tcp_mark_push len: %u\n", 
// 				len);
// 	return 0;
// }

SEC("fentry/tso_fragment")
int BPF_PROG(tso_fragment, struct sock *sk, struct sk_buff *skb, unsigned int len,
			unsigned int mss_now, gfp_t gfp)
{
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	unsigned int skb_len = BPF_CORE_READ(skb, len);
	int sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);
	int sk_sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
	if (family != AF_INET) {
        return 0;
    }
	
	if(lport == 8080)
	{
		bpf_printk("tso_fragment skb->len: %u, wmem: %d, sndbuf: %d\n", 
				skb_len, sk_wmem_queued, sk_sndbuf);
	}
	return 0;
}


SEC("fentry/ip_queue_xmit")
int BPF_PROG(ip_queue_xmit, struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	unsigned int skb_len = BPF_CORE_READ(skb, len);
	int sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);
	int sk_sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
	if (family != AF_INET) {
        return 0;
    }
	
	if(lport == 8080)
	{
		bpf_printk("ip_queue_xmit skb->len: %u, wmem: %d, sndbuf: %d\n", 
				skb_len, sk_wmem_queued, sk_sndbuf);
	}
	return 0;
}


SEC("tracepoint/tcp/tcp_probe")
int handle_tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	u16 sport = (u16)ctx->sport;
	u16 dport = (u16)ctx->dport;
	u16 family = (u16)ctx->family;
	u16 data_len = (u16)ctx->data_len;
	u32 snd_nxt = (u32)ctx->snd_nxt;
	u32 snd_una = (u32)ctx->snd_una;
	u32 snd_cwnd = (u32)ctx->snd_cwnd;
	u32 ssthresh = (u32)ctx->ssthresh;
	u32 rcv_wnd = (u32)ctx->rcv_wnd;

	if (family != AF_INET) {
        return 0;
    }

	if(sport == 8080 || dport == 8080)
	{
		bpf_printk("handle_tcp_probe data_len: %u, snd_cwnd: %u, rcv_wnd: %u, snd_nxt: %u, snd_una: %u\n", 
				data_len, snd_cwnd, rcv_wnd, snd_nxt, snd_una);
	}
	return 0;
}