// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include "sockfilter.h"
#include "sockfilter.skel.h"

static const char *ipproto_mapping[IPPROTO_MAX] = {
	[IPPROTO_IP] = "IP",	   [IPPROTO_ICMP] = "ICMP",	  [IPPROTO_IGMP] = "IGMP",
	[IPPROTO_IPIP] = "IPIP",   [IPPROTO_TCP] = "TCP",	  [IPPROTO_EGP] = "EGP",
	[IPPROTO_PUP] = "PUP",	   [IPPROTO_UDP] = "UDP",	  [IPPROTO_IDP] = "IDP",
	[IPPROTO_TP] = "TP",	   [IPPROTO_DCCP] = "DCCP",	  [IPPROTO_IPV6] = "IPV6",
	[IPPROTO_RSVP] = "RSVP",   [IPPROTO_GRE] = "GRE",	  [IPPROTO_ESP] = "ESP",
	[IPPROTO_AH] = "AH",	   [IPPROTO_MTP] = "MTP",	  [IPPROTO_BEETPH] = "BEETPH",
	[IPPROTO_ENCAP] = "ENCAP", [IPPROTO_PIM] = "PIM",	  [IPPROTO_COMP] = "COMP",
	[IPPROTO_SCTP] = "SCTP",   [IPPROTO_UDPLITE] = "UDPLITE", [IPPROTO_MPLS] = "MPLS",
	[IPPROTO_RAW] = "RAW"
};

static int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (sock < 0) {
		fprintf(stderr, "Failed to create raw socket\n");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		fprintf(stderr, "Failed to bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct so_event *e = data;
	char ifname[IF_NAMESIZE];

	if (e->pkt_type != PACKET_HOST)
		return 0;

	if (e->ip_proto < 0 || e->ip_proto >= IPPROTO_MAX)
		return 0;

	if (!if_indextoname(e->ifindex, ifname))
		return 0;

	printf("interface: %s\tprotocol: %s\t%s:%d(src) -> %s:%d(dst)\n", ifname,
	       ipproto_mapping[e->ip_proto], inet_ntoa((struct in_addr){ e->src_addr }),
	       ntohs(e->port16[0]), inet_ntoa((struct in_addr){ e->dst_addr }),
	       ntohs(e->port16[1]));

	return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct sockfilter_bpf *skel;
	int err, prog_fd, sock;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF programs*/
	skel = sockfilter_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Create raw socket for localhost interface */
	sock = open_raw_sock("lo");
	if (sock < 0) {
		err = -2;
		fprintf(stderr, "Failed to open raw socket\n");
		goto cleanup;
	}

	/* Attach BPF program to raw socket */
	prog_fd = bpf_program__fd(skel->progs.socket_handler);
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
		err = -3;
		fprintf(stderr, "Failed to attach to raw socket\n");
		goto cleanup;
	}

	/* Process events */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
		sleep(1);
	}

cleanup:
	ring_buffer__free(rb);
	sockfilter_bpf__destroy(skel);
	return -err;
}
