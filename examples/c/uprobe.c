// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

/*
 * Taken from https://github.com/torvalds/linux/blob/9b59ec8d50a1f28747ceff9a4f39af5deba9540e/tools/testing/selftests/bpf/trace_helpers.c#L149-L205
 *
 * See discussion in https://github.com/libbpf/libbpf-bootstrap/pull/90
 */
ssize_t get_uprobe_offset(const void *addr)
{
	size_t start, end, base;
	char buf[256];
	bool found = false;
	FILE *f;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return -errno;

	while (fscanf(f, "%zx-%zx %s %zx %*[^\n]\n", &start, &end, buf, &base) == 4) {
		if (buf[2] == 'x' && (uintptr_t)addr >= start && (uintptr_t)addr < end) {
			found = true;
			break;
		}
	}

	fclose(f);

	if (!found)
		return -ESRCH;

	return (uintptr_t)addr - start + base;
}

/* It's a global function to make sure compiler doesn't inline it. */
int uprobed_add(int a, int b)
{
	return a + b;
}

int uprobed_sub(int a, int b)
{
	return a - b;
}

int main(int argc, char **argv)
{
	struct uprobe_bpf *skel;
	long uprobe_offset;
	int err, i;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* uprobe/uretprobe expects relative offset of the function to attach
	 * to. This offset is relateve to the process's base load address. So
	 * easy way to do this is to take an absolute address of the desired
	 * function and substract base load address from it.  If we were to
	 * parse ELF to calculate this function, we'd need to add .text
	 * section offset and function's offset within .text ELF section.
	 */
	uprobe_offset = get_uprobe_offset(&uprobed_add);

	/* Attach tracepoint handler */
	skel->links.uprobe_add =
		bpf_program__attach_uprobe(skel->progs.uprobe_add, false /* not uretprobe */,
					   0 /* self pid */, "/proc/self/exe", uprobe_offset);

	if (!skel->links.uprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
	 * processes that use the same binary executable; to do that we need
	 * to specify -1 as PID, as we do here
	 */
	skel->links.uretprobe_add =
		bpf_program__attach_uprobe(skel->progs.uretprobe_add, true /* uretprobe */,
					   -1 /* any pid */, "/proc/self/exe", uprobe_offset);

	if (!skel->links.uretprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	err = uprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (i = 0;; i++) {
		/* trigger our BPF programs */
		fprintf(stderr, ".");
		uprobed_add(i, i + 1);
		uprobed_sub(i * i, i);
		sleep(1);
	}

cleanup:
	uprobe_bpf__destroy(skel);
	return -err;
}
