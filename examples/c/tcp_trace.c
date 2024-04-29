#include <argp.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "tcp_trace.skel.h"

static struct env {
	pid_t pid;
	bool lport;
} env;

const char *argp_program_version = "tcp_trace 0.1";
const char *argp_program_bug_address = "";
const char argp_program_doc[] =
"\nTrace TCP connects and show connection latency.\n"
"\n"
"USAGE: tcpconnlat [--help] [-t] [-p PID] [-L]\n"
"\n"
"EXAMPLES:\n"
"    tcpconnlat              # summarize on-CPU time as a histogram\n"
"    tcpconnlat 1            # trace connection latency slower than 1 ms\n"
"    tcpconnlat 0.1          # trace connection latency slower than 100 us\n"
"    tcpconnlat -t           # 1s summaries, milliseconds, and timestamps\n"
"    tcpconnlat -p 185       # trace PID 185 only\n"
"    tcpconnlat -L           # include LPORT while printing outputs\n";

static const struct argp_option opts[] = {
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "lport", 'L', NULL, 0, "Include LPORT on output" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
		break;
	case 'L':
		env.lport = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// static int handle_event(void *ctx, void *data, size_t data_sz)
// {
// 	const struct so_event *e = data;
// 	char ifname[IF_NAMESIZE];
// 	char sstr[16] = {}, dstr[16] = {};

// 	if (e->pkt_type != PACKET_HOST)
// 		return 0;

// 	if (e->ip_proto < 0 || e->ip_proto >= IPPROTO_MAX)
// 		return 0;

// 	if (!if_indextoname(e->ifindex, ifname))
// 		return 0;

// 	ltoa(ntohl(e->src_addr), sstr);
// 	ltoa(ntohl(e->dst_addr), dstr);

// 	printf("interface: %s\tprotocol: %s\t%s:%d(src) -> %s:%d(dst)\n", ifname,
// 	       ipproto_mapping[e->ip_proto], sstr, ntohs(e->port16[0]), dstr, ntohs(e->port16[1]));

// 	return 0;
// }

int app_run(void)
{

	struct tcp_trace_bpf *skel;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	skel = tcp_trace_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	skel->rodata->targ_tgid = env.pid;

	/* Load & verify BPF programs */
	int err = tcp_trace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = tcp_trace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	// rb = ring_buffer__new(bpf_map__fd(skel->maps.pid_2_flow_map), handle_event, NULL, NULL);
	// if (!rb) {
	// 	err = -1;
	// 	fprintf(stderr, "Failed to create ring buffer\n");
	// 	goto cleanup;
	// }

	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	tcp_trace_bpf__destroy(skel);
	return -err;
}
 
int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

   return app_run();
}