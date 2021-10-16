// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static struct env
{
	bool verbose;
	long min_duration_ms;
	char *procname;
	int total;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
	"BPF bootstrap demo application.\n"
	"\n"
	"It traces process start and exits and shows associated \n"
	"information (filename, process duration, PID and PPID, etc).\n"
	"\n"
	"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{"verbose", 'v', NULL, 0, "Verbose debug output"},
	{"duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report"},
	{"duration", 'p', "PROCESS-NAME", 0, "Process name"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		env.procname = arg;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0)
		{
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	
	if (e->mem_event)
	{
		if (e->is_mmap)
		{
			env.total += e->page_size;
			printf("%-8s %-6s %-16s %-7d %-7d  %-16d %-16d\n",
				   ts, "MMAP", e->comm, e->pid, e->ppid, e->page_size, env.total);
		}
		else
		{
			env.total -= e->page_size;
			printf("%-8s %-6s %-16s %-7d %-7d -%-16d %-16d\n",
				   ts, "MUNMAP", e->comm, e->pid, e->ppid, e->page_size, env.total);
		}
	}

	return 0;
}

void spawnChild(int ppid, char** arg_list){
	pid_t ch_pid = fork();
    if (ch_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

	if (ch_pid == 0) {
        execvp(env.procname, arg_list);
        printf("spawned child with pid - %d\n", ch_pid);
		exit(0);
    } else if (ch_pid == ppid) {
        printf("I'm parent. My child got right pid!\n");
    } 
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct bootstrap_bpf *skel;
	int err;

	/* (stdlib) Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* (libbpf(here)) Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* (here) Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* (here) Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* (libbpf) Load and verify BPF application */
	skel = bootstrap_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
	strcpy(skel->rodata->proc, env.procname);

	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = bootstrap_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	/* ensure BPF program only handles write() syscalls from our process */
	skel->bss->my_pid = getpid();

	/* Process events */
	printf("%-8s %-5s %-16s %-7s %-7s %-16s %s\n",
		   "TIME", "EVENT", "COMM", "PID", "PPID", "REQUESTED BYTES", "TOTAL");

	bool spawned = false;
	// pid_t child;
	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		if (!spawned){
    		char *args[] = { env.procname, NULL, NULL };
			spawnChild(getpid(),args);
			spawned=true;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	bootstrap_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
