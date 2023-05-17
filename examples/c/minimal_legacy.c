/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "minimal_legacy.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct minimal_legacy_bpf *skel;
	int err;
	pid_t pid;
	unsigned index = 0;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = minimal_legacy_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* ensure BPF program only handles write() syscalls from our process */
	pid = getpid();
	err = bpf_map__update_elem(skel->maps.my_pid_map, &index, sizeof(index), &pid,
				   sizeof(pid_t), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Error updating map with pid: %s\n", strerror(err));
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = minimal_legacy_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	minimal_legacy_bpf__destroy(skel);
	return -err;
}
