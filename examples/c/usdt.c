// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include <setjmp.h>
#include <linux/limits.h>
#include "usdt.skel.h"

static volatile sig_atomic_t exiting;
static const char *usdt_provider = "libc";
static const char *usdt_name = "setjmp";
static jmp_buf env;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int get_libc_path(char *path)
{
	FILE *f;
	char buf[PATH_MAX] = {};
	char *filename;
	float version;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return -errno;

	while (fscanf(f, "%*x-%*x %*s %*s %*s %*s %[^\n]\n", buf) != EOF) {
		if (strchr(buf, '/') != buf)
			continue;
		filename = strrchr(buf, '/') + 1;
		if (sscanf(filename, "libc-%f.so", &version) == 1) {
			memcpy(path, buf, strlen(buf));
			fclose(f);
			return 0;
		}
	}

	fclose(f);
	return -1;
}

static void usdt_trigger() {
	setjmp(env);
}

int main(int argc, char **argv)
{
	char libc_path[PATH_MAX] = {};
	struct usdt_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
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

	err = get_libc_path(libc_path);
	if (err) {
		fprintf(stderr, "Failed to get libc path\n");
		goto cleanup;
	}

	/*
	 * Manually attach to libc.so we find.
	 * We specify pid here, so we don't have to do pid filtering in BPF program.
	 */
	skel->links.usdt_manual_attach = bpf_program__attach_usdt(skel->progs.usdt_manual_attach, getpid(),
								  libc_path, usdt_provider, usdt_name, NULL);
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
