// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 Meta */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include "task_iter.h"
#include "task_iter.skel.h"

static struct env {
	bool verbose;
} env;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static const char *get_task_state(__u32 state)
{
	/* Taken from:
	 * https://elixir.bootlin.com/linux/latest/source/include/linux/sched.h#L85
	 * There are a lot more states not covered here but these are common ones.
	 */
	switch (state) {
	case 0x0000: return "RUNNING";
	case 0x0001: return "INTERRUPTIBLE";
	case 0x0002: return "UNINTERRUPTIBLE";
	case 0x0200: return "WAKING";
	case 0x0400: return "NOLOAD";
	case 0x0402: return "IDLE";
	case 0x0800: return "NEW";
	default: return "<unknown>";
	}
}

int main(int argc, char **argv)
{
	struct task_iter_bpf *skel;
	struct task_info buf;
	int iter_fd;
	ssize_t ret;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Open, load, and verify BPF application */
	skel = task_iter_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = task_iter_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.get_tasks));
	if (iter_fd < 0) {
		err = -1;
		fprintf(stderr, "Failed to create iter\n");
		goto cleanup;
	}

	while (true) {
		ret = read(iter_fd, &buf, sizeof(struct task_info));
		if (ret < 0) {
			if (errno == EAGAIN)
				continue;
			err = -errno;
			break;
		}
		if (ret == 0)
			break;
		if (buf.kstack_len <= 0) {
			printf("Error getting kernel stack for task. Task Info. Pid: %d. Process Name: %s. Kernel Stack Error: %d. State: %s\n",
			       buf.pid, buf.comm, buf.kstack_len, get_task_state(buf.state));
		} else {
			printf("Task Info. Pid: %d. Process Name: %s. Kernel Stack Len: %d. State: %s\n",
			       buf.pid, buf.comm, buf.kstack_len, get_task_state(buf.state));
		}
	}

cleanup:
	/* Clean up */
	close(iter_fd);
	task_iter_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
