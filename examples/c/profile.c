// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Facebook */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>
#include <sys/time.h>
#include <sys/signal.h>

#include "profile.skel.h"
#include "profile.h"
#include "blazesym.h"
#include "hashmap.h"

/*
 * This function is from libbpf, but it is not a public API and can only be
 * used for demonstration. We can use this here because we statically link
 * against the libbpf built from submodule during build.
 */
extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
			    unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

static struct blaze_symbolizer *symbolizer;

static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info* code_info)
{
	/* If we have an input address we have a new symbol. */
	if (input_addr != 0) {
		printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			printf(" %s:%u\n", code_info->file, code_info->line);
		} else {
			printf("\n");
		}
	} else {
		printf("%16s  %s", "", name);
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
	const struct blaze_result *result;
	const struct blaze_sym *sym;
	int i, j;

	assert(sizeof(uintptr_t) == sizeof(uint64_t));

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = pid,
		};
		result = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	} else {
		struct blaze_symbolize_src_kernel src = {
			.type_size = sizeof(src),
		};
		result = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}

	if (result == NULL) {
		printf("  failed to symbolize addresses: %s\n", blaze_err_str(blaze_err_last()));
		return;
	}

	for (i = 0; i < stack_sz; i++) {
		if (!result || result->cnt <= i || result->syms[i].name == NULL) {
			printf("%016llx: <no-symbol>\n", stack[i]);
			continue;
		}

		sym = &result->syms[i];
		print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

		for (j = 0; j < sym->inlined_cnt; j++) {
			inlined = &sym->inlined[j];
			print_frame(sym->name, 0, 0, 0, &inlined->code_info);
		}
	}

	blaze_result_free(result);
}

static long task_id(int pid, int cpu_id)
{
	return pid ?: -(cpu_id + 1);
}

#define STATS_PERIOD_MS 5000

struct task_stats {
	uint32_t on_cpu_us;
	uint32_t off_cpu_us;
};

static struct hashmap *stats;
static bool verbose;

static size_t hash_identity_fn(long key, void *ctx)
{
	return key;
}

static bool hash_equal_fn(long k1, long k2, void *ctx)
{
	return k1 == k2;
}

static void sig_timer(int sig)
{
	struct hashmap_entry *cur, *tmp;
	int bkt;
	union {
		struct task_stats st;
		long opaque;
	} v;

	printf("===============================\n");
	hashmap__for_each_entry_safe(stats, cur, tmp, bkt) {
		v.opaque = cur->value;
		if (cur->key < 0) {
			printf("IDLE(%ld): ONCPU = %ums OFFCPU = %ums\n",
			       -cur->key - 1, v.st.on_cpu_us / 1000, v.st.off_cpu_us / 1000);
		} else {
			printf("PID(%ld): ONCPU = %ums OFFCPU = %ums\n",
			       cur->key, v.st.on_cpu_us / 1000, v.st.off_cpu_us / 1000);
		}

		hashmap__delete(stats, cur->key, NULL, NULL);
	}
	printf("-------------------------------\n");
}

/* Receive events from the ring buffer. */
static int event_handler(void *_ctx, void *data, size_t size)
{
	struct wprof_event *e = data;
	const char *status;
	unsigned long key = task_id(e->tgid, e->cpu_id);
	union {
		long opaque;
		struct task_stats stats;
	} v;

	if (!hashmap__find(stats, key, &v.opaque))
		v.opaque = 0;

	switch (e->kind) {
	case EV_ON_CPU:
		status = "ONCPU";
		v.stats.on_cpu_us += e->duration_ns / 1000;
		break;
	case EV_OFF_CPU:
		status = "OFFCPU";
		v.stats.off_cpu_us += e->duration_ns / 1000;
		break;
	case EV_TIMER:
		status = "TIMER";
		v.stats.on_cpu_us += e->duration_ns / 1000;
		break;
	default: status = "UNKNOWN"; break;
	}

	hashmap__set(stats, key, v.opaque, NULL, NULL);

	if (!verbose)
		return 0;

	printf("%s (%d/%d) @ CPU %d %s %lldus\n", e->comm, e->pid, e->tgid, e->cpu_id,
	       status, e->duration_ns / 1000);

	if (e->kstack_sz <= 0 && e->ustack_sz <= 0)
		return 1;

	if (e->kstack_sz > 0) {
		printf("Kernel:\n");
		show_stack_trace(e->kstack, e->kstack_sz / sizeof(__u64), 0);
	} else {
		printf("No Kernel Stack\n");
	}

	if (e->ustack_sz > 0) {
		printf("Userspace:\n");
		show_stack_trace(e->ustack, e->ustack_sz / sizeof(__u64), e->pid);
	} else {
		printf("No Userspace Stack\n");
	}

	printf("\n");

	return 0;
}

static __u64 ktime_off;

static inline uint64_t timespec_to_ns(struct timespec *ts)
{
	return ts->tv_sec * 1000000000ULL + ts->tv_nsec;
}

static void calibrate_ktime(void)
{
	int i;
	struct timespec t1, t2, t3;
	uint64_t best_delta = 0, delta, ts;

	for (i = 0; i < 10; i++) {
		clock_gettime(CLOCK_REALTIME, &t1);
		clock_gettime(CLOCK_MONOTONIC, &t2);
		clock_gettime(CLOCK_REALTIME, &t3);

		delta = timespec_to_ns(&t3) - timespec_to_ns(&t1);
		ts = (timespec_to_ns(&t3) + timespec_to_ns(&t1)) / 2;

		if (i == 0 || delta < best_delta) {
			best_delta = delta;
			ktime_off = ts - timespec_to_ns(&t2);
		}
	}
}

static __u64 ktime_now_ns()
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);

	return timespec_to_ns(&t);
}

static void show_help(const char *progname)
{
	printf("Usage: %s [-f <frequency>] [-h]\n", progname);
}

int main(int argc, char *const argv[])
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	int freq = 1, pid = -1, cpu = -1;
	struct profile_bpf *skel = NULL;
	struct perf_event_attr attr;
	struct bpf_link **links = NULL;
	struct ring_buffer *ring_buf = NULL;
	int num_cpus, num_online_cpus;
	int *pefds = NULL, pefd;
	int argp, i, err = 0;
	bool *online_mask = NULL;
	struct itimerval timer_ival;

	while ((argp = getopt(argc, argv, "hf:p:c:")) != -1) {
		switch (argp) {
		case 'v':
			verbose = true;
			break;
		case 'f':
			freq = atoi(optarg);
			if (freq < 1)
				freq = 1;
			break;
		case 'p':
			pid = atoi(optarg);
			if (pid < 0) {
				fprintf(stderr, "couldn't parse PID\n");
				return 1;
			}
			break;
		case 'c':
			cpu = atoi(optarg);
			if (cpu < 0) {
				fprintf(stderr, "couldn't parse CPU ID\n");
				return 1;
			}
			break;
		case 'h':
		default:
			show_help(argv[0]);
			return 1;
		}
	}

	stats = hashmap__new(hash_identity_fn, hash_equal_fn, NULL);

	err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
	if (err) {
		fprintf(stderr, "Fail to get online CPU numbers: %d\n", err);
		goto cleanup;
	}

	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		fprintf(stderr, "Fail to get the number of processors\n");
		err = -1;
		goto cleanup;
	}

	calibrate_ktime();

	skel = profile_bpf__open();
	if (!skel) {
		fprintf(stderr, "Fail to open and load BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	if (cpu >= 0)
		skel->rodata->cpu_id = cpu;

	err = profile_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Fail to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		fprintf(stderr, "Fail to create a symbolizer\n");
		err = -1;
		goto cleanup;
	}

	/* Prepare ring buffer to receive events from the BPF program. */
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.rb), event_handler, NULL, NULL);
	if (!ring_buf) {
		err = -1;
		goto cleanup;
	}

	pefds = malloc(num_cpus * sizeof(int));
	for (i = 0; i < num_cpus; i++) {
		pefds[i] = -1;
	}

	links = calloc(num_cpus, sizeof(struct bpf_link *));

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_SOFTWARE;
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	attr.sample_freq = freq;
	attr.freq = 1;

	for (cpu = 0; cpu < num_cpus; cpu++) {
		/* skip offline/not present CPUs */
		if (cpu >= num_online_cpus || !online_mask[cpu])
			continue;

		/* Set up performance monitoring on a CPU/Core */
		pefd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			fprintf(stderr, "Fail to set up performance monitor on a CPU/Core\n");
			err = -1;
			goto cleanup;
		}
		pefds[cpu] = pefd;

		/* Attach a BPF program on a CPU */
		links[cpu] = bpf_program__attach_perf_event(skel->progs.wprof_tick, pefd);
		if (!links[cpu]) {
			err = -1;
			goto cleanup;
		}
	}

	err = profile_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach skeleton: %d\n", err);
		goto cleanup;
	}

	skel->bss->session_start_ts = ktime_now_ns();

	signal(SIGALRM, sig_timer);

	timer_ival.it_value.tv_sec = STATS_PERIOD_MS / 1000;
	timer_ival.it_value.tv_usec = STATS_PERIOD_MS * 1000 % 1000000;
	timer_ival.it_interval = timer_ival.it_value;
	err = setitimer(ITIMER_REAL, &timer_ival, NULL);
	if (err < 0) {
		fprintf(stderr, "Failed to setup stats timer: %d\n", err);
		goto cleanup;
	}

	/* Wait and receive stack traces */
	while ((err = ring_buffer__poll(ring_buf, -1)) >= 0 || err == -EINTR) {
	}

cleanup:
	if (links) {
		for (cpu = 0; cpu < num_cpus; cpu++)
			bpf_link__destroy(links[cpu]);
		free(links);
	}
	if (pefds) {
		for (i = 0; i < num_cpus; i++) {
			if (pefds[i] >= 0)
				close(pefds[i]);
		}
		free(pefds);
	}
	ring_buffer__free(ring_buf);
	profile_bpf__destroy(skel);
	blaze_symbolizer_free(symbolizer);
	free(online_mask);
	return -err;
}
