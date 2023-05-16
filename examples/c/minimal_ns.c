// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 Hosein Bakhtiari */
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "minimal_ns.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct minimal_ns_bpf *skel;
	int err;
	struct stat sb;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = minimal_ns_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* ensure BPF program only handles write() syscalls from our process */
	if (stat("/proc/self/ns/pid", &sb) == -1) {
		fprintf(stderr, "Failed to acquire namespace information");
		return 1;
	}
	skel->bss->dev = sb.st_dev;
	skel->bss->ino = sb.st_ino;
	skel->bss->my_pid = getpid();

	/* Load & verify BPF programs */
	err = minimal_ns_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = minimal_ns_bpf__attach(skel);
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
	minimal_ns_bpf__destroy(skel);
	return -err;
}
