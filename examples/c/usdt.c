// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include <setjmp.h>
#include <linux/limits.h>
#include "usdt.skel.h"

static volatile sig_atomic_t exiting;
static jmp_buf env;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void usdt_trigger()
{
	setjmp(env);
}

int main(int argc, char **argv)
{
	struct usdt_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	skel = usdt_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->bss->my_pid = getpid();

	err = usdt_bpf__load(skel);
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		return 1;
	}

	/*
	 * Manually attach to libc.so we find.
	 * We specify pid here, so we don't have to do pid filtering in BPF program.
	 */
	skel->links.usdt_manual_attach = bpf_program__attach_usdt(
		skel->progs.usdt_manual_attach, getpid(), "libc.so.6", "libc", "setjmp", NULL);
	if (!skel->links.usdt_manual_attach) {
		err = errno;
		fprintf(stderr, "Failed to attach BPF program `usdt_manual_attach`\n");
		goto cleanup;
	}

	/*
	 * Auto attach by libbpf, libbpf should be able to find libc.so in your system.
	 * By default, auto attach does NOT specify pid, so we do pid filtering in BPF program
	 */
	err = usdt_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	while (!exiting) {
		/* trigger our BPF programs */
		usdt_trigger();
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	usdt_bpf__destroy(skel);
	return -err;
}
