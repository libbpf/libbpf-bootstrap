// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "snooper.skel.h"
#include "snooper.h"
#include "blazesym.h"

static struct blaze_symbolizer *symbolizer;
static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr,
			uint64_t offset, const blaze_symbolize_code_info* code_info)
{
	if (input_addr != 0) {
		printf("    %016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			printf(" %s:%u\n", code_info->file, code_info->line);
		} else {
			printf("\n");
		}
	} else {
		printf("    %16s  %s", "", name);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
		} else {
			printf("[inlined]\n");
		}
	}
}

static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
	const struct blaze_symbolize_inlined_fn* inlined;
	const struct blaze_syms *syms;
	const struct blaze_sym *sym;
	int i, j;

	assert(sizeof(uintptr_t) == sizeof(uint64_t));

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = pid,
		};

		syms = blaze_symbolize_process_abs_addrs(symbolizer, &src,
							 (const uintptr_t *)stack, stack_sz);
	} else {
		struct blaze_symbolize_src_kernel src = {
			.type_size = sizeof(src),
		};

		syms = blaze_symbolize_kernel_abs_addrs(symbolizer, &src,
							(const uintptr_t *)stack, stack_sz);
	}

	if (!syms) {
		printf("    failed to symbolize addresses: %s\n", blaze_err_str(blaze_err_last()));
		return;
	}

	for (i = 0; i < stack_sz; i++) {
		if (!syms || syms->cnt <= i || syms->syms[i].name == NULL) {
			printf("    %016llx: <no-symbol>\n", stack[i]);
			continue;
		}

		sym = &syms->syms[i];
		print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

		for (j = 0; j < sym->inlined_cnt; j++) {
			inlined = &sym->inlined[j];
			print_frame(inlined->name, 0, 0, 0, &inlined->code_info);
		}
	}

	blaze_syms_free(syms);
}

/* Ringbuf callback for task events */
static int handle_event(void *ctx, void *data, size_t size)
{
	struct task_event *event = data;

	printf("Task: %s (PID=%d, TID=%d)\n", event->comm, event->pid, event->tid);

	/* Show kernel stack trace */
	if (event->kstack_sz > 0) {
		printf("  Kernel stack:\n");
		show_stack_trace(event->kstack, event->kstack_sz / sizeof(__u64), 0);
	} else if (event->kstack_sz < 0) {
		printf("  Kernel stack error: %d\n", event->kstack_sz);
	} else {
		printf("  No kernel stack\n");
	}

	/* Show user stack trace */
	if (event->ustack_sz > 0) {
		printf("  User stack:\n");
		show_stack_trace(event->ustack, event->ustack_sz / sizeof(__u64), event->pid);
	} else if (event->ustack_sz < 0) {
		printf("  User stack error: %d\n", event->ustack_sz);
	} else {
		printf("  No user stack\n");
	}

	printf("\n");
	return 0;
}

static void show_help(const char *progname)
{
	printf("Usage: %s <PID>\n", progname);
	printf("  PID   Process ID to filter tasks (required)\n");
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct snooper_bpf *skel = NULL;
	LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo;
	pid_t pid_filter = 0;
	int iter_fd = -1;
	int err = 0;
	char dummy;

	if (argc < 2) {
		show_help(argv[0]);
		return 1;
	}

	errno = 0;
	pid_filter = (pid_t)strtol(argv[1], NULL, 10);
	err = -errno;
	if (err != 0 || pid_filter <= 0) {
		fprintf(stderr, "Failed to parse PID '%s'\n", argv[1]);
		show_help(argv[0]);
		return 1;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = snooper_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		fprintf(stderr, "Failed to create symbolizer\n");
		err = -1;
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = -1;
		goto cleanup;
	}

	memset(&linfo, 0, sizeof(linfo));
	linfo.task.pid = pid_filter;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	skel->links.snoop_tasks = bpf_program__attach_iter(skel->progs.snoop_tasks, &opts);
	if (!skel->links.snoop_tasks) {
		err = -errno;
		fprintf(stderr, "Failed to attach BPF iterator\n");
		goto cleanup;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.snoop_tasks));
	if (iter_fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed to create iterator\n");
		goto cleanup;
	}

	printf("Snooping on tasks for PID %d...\n\n", pid_filter);

	/* trigger task iterator program */
	while (read(iter_fd, &dummy, sizeof(dummy)) > 0) {
		/* nothing */
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout */);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
		if (err == 0)
			break;
	}

cleanup:
	if (iter_fd >= 0)
		close(iter_fd);
	ring_buffer__free(rb);
	snooper_bpf__destroy(skel);
	blaze_symbolizer_free(symbolizer);

	return err < 0 ? -err : 0;
}
