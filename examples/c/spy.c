// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "minimal.skel.h"
#include "spy.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}
/* This struct must match exactly what is in your spy.bpf.c */
struct event {
    int pid;
    char comm[16];
    char filename[256];
};

/* The Callback: This is called every time a new event arrives */
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    
    /* Clean output for the Python Brain to read */
    printf("%d,%s,%s\n", e->pid, e->comm, e->filename);
    fflush(stdout); 
    return 0;
}
int main(int argc, char **argv) {
    struct spy_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    skel = spy_bpf__open_and_load();
    if (!skel) return 1;

    err = spy_bpf__attach(skel);
    if (err) goto cleanup;

    /* Set up the Ring Buffer manager to use our handle_event function */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("KernelSpy Active. Streaming to Brain...\n");

    /* Poll the buffer infinitely */
    while (true) {
        err = ring_buffer__poll(rb, 100 /* timeout in ms */);
        if (err == -EINTR) continue;
        if (err < 0) break;
    }

cleanup:
    ring_buffer__free(rb);
    spy_bpf__destroy(skel);
    return 0;
}
