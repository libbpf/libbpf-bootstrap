// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include "tc.skel.h"


#include <net/if.h>
#include <arpa/inet.h>


#define LO_IFINDEX	1

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
        int ifindex;
        uint16_t nodeport;
        struct in_addr   be1, be2;

        /* Nodeport demo program, assumes 2 backends always for demo */

        if (argc < 5) {
                fprintf(stderr, "Usage: tc <interface_name> <nodeport> <be pod ip1> <be pod ip2>\n");
                return 1;
        }

        ifindex = if_nametoindex(argv[1]);
        if (!ifindex) {
                fprintf(stderr, "Bad interface name\n");
                return 1;
        }

        nodeport = atoi(argv[2]);
        if (nodeport < 30000 || nodeport > 32000) {
                fprintf(stderr, "Nodeport value must be in range <30000, 32000>\n");
                return 1;
        }

        inet_aton(argv[3], &be1);
        inet_aton(argv[4], &be2);

        if (be1.s_addr == 0  || be2.s_addr == 0) {
                fprintf(stderr, "Invalid backend IP values\n");
                return 1;
        }

       printf("Debug: nodeport %u  be1  0x%X    be2   0x%X\n", nodeport , (uint) be1.s_addr, 
                      (uint)be2.s_addr); 

/**
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
		.ifindex = LO_IFINDEX, .attach_point = BPF_TC_INGRESS);
**/
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
		.ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
		.handle = 1, .priority = 1);
	bool hook_created = false;
	struct tc_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	skel = tc_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */
	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");

	while (!exiting) {
		fprintf(stderr, ".");
		sleep(1);
	}

	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

cleanup:
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	tc_bpf__destroy(skel);
	return -err;
}
