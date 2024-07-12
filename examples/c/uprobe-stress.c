// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include "uprobe-stress.h"
#include "uprobe-stress.skel.h"

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))

static inline int rand_num(int max)
{
	return (unsigned)rand() % max;
}

static inline void atomic_inc(long *value)
{
	(void)__atomic_add_fetch(value, 1, __ATOMIC_RELAXED);
}

static inline void atomic_add(long *value, long n)
{
	(void)__atomic_add_fetch(value, n, __ATOMIC_RELAXED);
}

static inline long atomic_swap(long *value, long n)
{
	return __atomic_exchange_n(value, n, __ATOMIC_RELAXED);
}

static inline long atomic_load(long *value)
{
	return __atomic_load_n(value, __ATOMIC_RELAXED);
}

static unsigned long long time_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

#define UPROBE_MAX_DEPTH 72

#define ATTACH_MAX_LINKS_PER_THREAD 5
#define ATTACH_MAX_PROBES_PER_LINK 10
#define ATTACH_MAX_SLEEP_US (25 * 1000)

#define MMAP_MAX_MMAPS_PER_THREAD 10
#define MMAP_MAX_SLEEP_US (1 * 1000)

#define FORK_MAX_FORKS_PER_THREAD 10
#define FORK_MAX_SLEEP_US (1000 * 1000)
#define FORK_MAX_RUN_TIME_MS 20

struct trig_stats {
	long total_calls;
};

struct attach_stats {
	long total_links;
	long total_uprobes;
	long total_uretprobes;
};

struct mmap_stats {
	long total_mmaps;
};

struct fork_stats {
	long total_forks;
};

struct all_stats {
	struct trig_stats trig;
	struct attach_stats attach;
	struct mmap_stats mmap;
	struct fork_stats fork;
	long uprobe_hits;
	long uretprobe_hits;
};

static struct env {
	bool verbose;

	bool child_mode;
	int child_run_time_ms;

	struct uprobe_stress_bpf *skel;

	pthread_t *trig_threads;
	struct trig_stats **trig_stats;
	int trig_thread_cnt;
	int uprobe_max_depth;
	int uprobe_fn_cnt;

	pthread_t *attach_threads;
	struct attach_stats **attach_stats;
	int attach_thread_cnt;
	int attach_max_links_per_thread;
	int attach_max_probes_per_link;
	int attach_max_sleep_us;

	pthread_t *mmap_threads;
	struct mmap_stats **mmap_stats;
	int mmap_thread_cnt;
	int mmap_max_mmaps_per_thread;
	int mmap_max_sleep_us;

	pthread_t *fork_threads;
	struct fork_stats **fork_stats;
	int fork_thread_cnt;
	int fork_max_forks_per_thread;
	int fork_max_sleep_us;
	int fork_max_run_time_ms;

	pthread_t stats_thread;
	int stats_period_ms;
} env = {
	.uprobe_max_depth = UPROBE_MAX_DEPTH,

	.trig_thread_cnt = 1,
	.attach_thread_cnt = 1,
	.mmap_thread_cnt = 1,
	.fork_thread_cnt = 1,

	.attach_max_links_per_thread = ATTACH_MAX_LINKS_PER_THREAD,
	.attach_max_probes_per_link = ATTACH_MAX_PROBES_PER_LINK,
	.attach_max_sleep_us = ATTACH_MAX_SLEEP_US,

	.mmap_max_mmaps_per_thread = MMAP_MAX_MMAPS_PER_THREAD,
	.mmap_max_sleep_us = MMAP_MAX_SLEEP_US,

	.fork_max_forks_per_thread = FORK_MAX_FORKS_PER_THREAD,
	.fork_max_sleep_us = FORK_MAX_SLEEP_US,
	.fork_max_run_time_ms = FORK_MAX_RUN_TIME_MS,

	.stats_period_ms = 5000,
};

const char *argp_program_version = "uprobe-stress 0.0";
const char *argp_program_bug_address = "<andrii@kernel.org>";
const char argp_program_doc[] = "Uprobe/uretprobe kernel subsystem stress generator.\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "trigger-threads", 't', "COUNT", 0, "Number of triggering threads" },
	{ "attach-threads", 'a', "COUNT", 0, "Number of registration threads" },
	{ "mmap-threads", 'm', "COUNT", 0, "Number of mmaping threads" },
	{ "fork-threads", 'f', "COUNT", 0, "Number of forking threads" },
	{ "child", 'c', "RUN_TIME_MS", 0, "Child mode: trigger uprobes for specified amont of time" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 't':
		env.trig_thread_cnt = strtol(arg, NULL, 10);
		if (env.trig_thread_cnt <= 0) {
			fprintf(stderr, "Invalid trigger-threads: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'a':
		env.attach_thread_cnt = strtol(arg, NULL, 10);
		if (env.attach_thread_cnt <= 0) {
			fprintf(stderr, "Invalid attach-threads: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
		env.mmap_thread_cnt = strtol(arg, NULL, 10);
		if (env.mmap_thread_cnt <= 0) {
			fprintf(stderr, "Invalid mmap-threads: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'f':
		env.fork_thread_cnt = strtol(arg, NULL, 10);
		if (env.fork_thread_cnt <= 0) {
			fprintf(stderr, "Invalid fork-threads: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.child_mode = true;
		env.child_run_time_ms = strtol(arg, NULL, 10);
		if (env.child_run_time_ms < 0) {
			fprintf(stderr, "Invalid chilld run time: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	exiting = true;
}

#define __PASTE(a, b) a##b
#define PASTE(a, b) __PASTE(a, b)

#define NAME(name, idx) PASTE(name, idx)

#define F(body, name, idx) body(name, idx)

#define F10(body, name, idx) \
	F(body, PASTE(name, idx), 0) F(body, PASTE(name, idx), 1) F(body, PASTE(name, idx), 2) \
	F(body, PASTE(name, idx), 3) F(body, PASTE(name, idx), 4) F(body, PASTE(name, idx), 5) \
	F(body, PASTE(name, idx), 6) F(body, PASTE(name, idx), 7) F(body, PASTE(name, idx), 8) \
	F(body, PASTE(name, idx), 9)

#define F100(body, name, idx) \
	F10(body, PASTE(name, idx), 0) F10(body, PASTE(name, idx), 1) F10(body, PASTE(name, idx), 2) \
	F10(body, PASTE(name, idx), 3) F10(body, PASTE(name, idx), 4) F10(body, PASTE(name, idx), 5) \
	F10(body, PASTE(name, idx), 6) F10(body, PASTE(name, idx), 7) F10(body, PASTE(name, idx), 8) \
	F10(body, PASTE(name, idx), 9)

#define DEF(name, idx) int __attribute__((weak)) NAME(name, idx)(int depth) { return 1 + uprobe_mediator(depth); }
#define REF(name, idx) &NAME(name, idx),

static int uprobe_mediator(int depth);

/* define a bunch of uprobe functions */
F100(DEF, uprobe_, 0);

typedef int (*uprobe_fn)(int);

static uprobe_fn uprobe_fns[] = {
	F100(REF, uprobe_, 0)
};

static int uprobe_mediator(int depth) {
	int fn_idx;

	if (depth <= 0)
		return 0;

	fn_idx = rand_num(env.uprobe_fn_cnt);
	return uprobe_fns[fn_idx](depth - 1);
}

static long uprobe_offs[ARRAY_SIZE(uprobe_fns)];

static long get_uprobe_offset(const void *addr)
{
	size_t start, end, base;
	char buf[256];
	FILE *f;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return -errno;

	while (fscanf(f, "%zx-%zx %s %zx %*[^\n]\n", &start, &end, buf, &base) == 4) {
		if (buf[2] == 'x' && (uintptr_t)addr >= start && (uintptr_t)addr < end) {
			fclose(f);
			return (uintptr_t)addr - start + base;
		}
	}

	fclose(f);
	return -ESRCH;
}

static void *trig_thread(void *ctx)
{
	struct trig_stats *stats = calloc(1, sizeof(*stats));
	int thread_idx = (long)ctx;
	int depth;

	env.trig_stats[thread_idx] = stats;

	while (!exiting) {
		depth = rand_num(env.uprobe_max_depth);
		if (depth)
			atomic_add(&stats->total_calls, uprobe_mediator(depth));
	}

	return stats;
}

struct attach_state {
	int thread_idx;

	struct bpf_link **links;
	int link_cnt;

	unsigned long *offsets;
};

static void attacher_attach(struct attach_state *state, struct attach_stats *stats)
{
	int i, idx, err;
	LIBBPF_OPTS(bpf_uprobe_multi_opts, opts);
	struct bpf_link *link;

	if (state->link_cnt >= env.attach_max_links_per_thread)
		return;

	/* attach to random number of uprobes/uretprobes */
	opts.cnt = rand_num(env.attach_max_probes_per_link);
	if (opts.cnt == 0)
		return;

	opts.retprobe = rand_num(2) == 1;

	for (i = 0; i < opts.cnt; i++) {
		idx = rand_num(env.uprobe_fn_cnt);
		state->offsets[i] = uprobe_offs[idx];
	}
	opts.offsets = state->offsets;

	link = bpf_program__attach_uprobe_multi(
		opts.retprobe ? env.skel->progs.uretprobe : env.skel->progs.uprobe,
		rand_num(2) == 1 ? -1 : getpid(),
		"/proc/self/exe",
		NULL,
		&opts);

	if (!link) {
		err = -errno;
		fprintf(stderr, "Attacher #%d: failed to attach %s with %zu probes: %d\n",
			state->thread_idx, opts.retprobe ? "uretprobe" : "uprobes", opts.cnt, err);
		exit(1);
	}

	atomic_inc(&stats->total_links);
	if (opts.retprobe)
		atomic_add(&stats->total_uretprobes, opts.cnt);
	else
		atomic_add(&stats->total_uprobes, opts.cnt);

	state->links[state->link_cnt++] = link;
}

static void attacher_detach(struct attach_state *state, struct attach_stats *stats)
{
	int idx;

	if (state->link_cnt <= 0)
		return;

	/* detach random link */
	idx = rand_num(state->link_cnt);
	bpf_link__destroy(state->links[idx]);

	state->links[idx] = state->links[state->link_cnt - 1];
	state->link_cnt--;
}

static void attacher_sleep(struct attach_state *state, struct attach_stats *stats)
{
	usleep(rand_num(env.attach_max_sleep_us));
}

static void *attach_thread(void *ctx)
{
	int thread_idx = (long)ctx, i;
	struct attach_stats *stats = calloc(1, sizeof(*stats));
	struct attach_state *state = calloc(1, sizeof(*state));

	env.attach_stats[thread_idx] = stats;

	state->thread_idx = thread_idx;
	state->links = calloc(env.attach_max_links_per_thread, sizeof(*state->links));
	state->offsets = calloc(env.attach_max_probes_per_link, sizeof(*state->offsets));

	while (!exiting) {
		switch (rand_num(3)) {
		case 0: attacher_attach(state, stats); break;
		case 1: attacher_detach(state, stats); break;
		case 2: attacher_sleep(state, stats); break;
		default: fprintf(stderr, "ATTACH BOOM!\n"); exit(1);
		}
	}

	for (i = 0; i < state->link_cnt; i++) {
		bpf_link__destroy(state->links[i]);
	}

	return stats;
}

struct mmap_state {
	void **mmap_addrs;
	size_t *mmap_sizes;
	int mmap_cnt;
};

static void *mmap_thread(void *ctx)
{
	int thread_idx = (long)ctx;
	struct mmap_stats *stats = calloc(1, sizeof(*stats));
	struct mmap_state *state = calloc(1, sizeof(*state));
	int page_sz = sysconf(_SC_PAGESIZE);
	int fd, err, i;
	void *addr;
	long size;

	env.mmap_stats[thread_idx] = stats;

	state->mmap_addrs = calloc(env.mmap_max_mmaps_per_thread, sizeof(*state->mmap_addrs));
	state->mmap_sizes = calloc(env.mmap_max_mmaps_per_thread, sizeof(*state->mmap_sizes));

	fd = open("/proc/self/exe", O_RDONLY);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "Mmaper #%d: failed to open() /proc/self/exe: %d\n",
			thread_idx, err);
		exit(1);
	}

	while (!exiting) {
		switch (rand_num(3)) {
		case 0: { /* MMAP */
			long off, s1, s2, e1, e2;
			int idx1, idx2;

			if (state->mmap_cnt >= env.mmap_max_mmaps_per_thread)
				continue;

			idx1 = rand_num(env.uprobe_fn_cnt);
			idx2 = rand_num(env.uprobe_fn_cnt);
			s1 = uprobe_offs[idx1] / page_sz * page_sz;
			s2 = uprobe_offs[idx2] / page_sz * page_sz;
			e1 = (uprobe_offs[idx1] + page_sz - 1) / page_sz * page_sz;
			e2 = (uprobe_offs[idx2] + page_sz - 1) / page_sz * page_sz;
			s1 = s1 < s2 ? s1 : s2;
			e1 = e1 > e2 ? e1 : e2;
			size = e1 - s1;
			off = e1;

			addr = mmap(NULL, size, PROT_EXEC | PROT_READ, MAP_PRIVATE, fd, off);
			if (addr == MAP_FAILED) {
				err = -errno;
				fprintf(stderr, "Mmaper #%d: failed to mmap() /proc/self/exe with size %ld at offset %ld: %d\n",
					thread_idx, size, off, err);
				exit(1);
			}

			state->mmap_addrs[state->mmap_cnt] = addr;
			state->mmap_sizes[state->mmap_cnt] = size;
			state->mmap_cnt++;

			atomic_inc(&stats->total_mmaps);

			break;
		}
		case 1: { /* MUNMAP */
			int idx;

			if (state->mmap_cnt <= 0)
				continue;

			idx = rand_num(state->mmap_cnt);
			addr = state->mmap_addrs[idx];
			size = state->mmap_sizes[idx];

			err = munmap(addr, size);
			if (err) {
				err = -errno;
				fprintf(stderr, "Mmaper #%d: failed to munmap() at addr %p with size %ld: %d\n",
					thread_idx, addr, size, err);
				exit(1);
			}

			state->mmap_addrs[idx] = state->mmap_addrs[state->mmap_cnt - 1];
			state->mmap_sizes[idx] = state->mmap_sizes[state->mmap_cnt - 1];
			state->mmap_cnt--;

			break;
		}
		case 2: /* SLEEP */
			usleep(rand_num(env.mmap_max_sleep_us));
			break;
		default: fprintf(stderr, "MMAP BOOM!\n"); exit(1);
		}
	}

	for (i = 0; i < state->mmap_cnt; i++) {
		(void)munmap(state->mmap_addrs[i], state->mmap_sizes[i]);
	}

	return stats;
}

struct fork_state {
	int *child_pids;
	int child_cnt;
};

static void *fork_thread(void *ctx)
{
	int thread_idx = (long)ctx;
	struct fork_stats *stats = calloc(1, sizeof(*stats));
	struct fork_state *state = calloc(1, sizeof(*state));
	int pid, i, idx, err, child_run_time_ms;

	env.fork_stats[thread_idx] = stats;

	state->child_pids = calloc(env.fork_max_forks_per_thread, sizeof(*state->child_pids));

	while (!exiting) {
		switch (rand_num(3)) {
		case 0: /* FORK */
			if (state->child_cnt >= env.fork_max_forks_per_thread)
				continue;

			child_run_time_ms = rand_num(env.fork_max_run_time_ms);

			pid = fork();
			if (pid < 0) {
				err = -errno;
				fprintf(stderr, "Forker #%d: failed to fork(): %d\n",
					thread_idx, err);
				exit(1);
			} else if (pid > 0) { /* parent */
				state->child_pids[state->child_cnt++] = pid;
				atomic_inc(&stats->total_forks);
			} else if (pid == 0) { /* child */
				char buf[32];
				char *argv[] = { "./uprobe-stress", "--child", NULL, NULL };

				snprintf(buf, sizeof(buf), "%d", child_run_time_ms);
				argv[2] = buf;

				exit(execve("/proc/self/exe", argv, NULL));
			}
			break;
		case 1: /* WAIT */
			if (state->child_cnt <= 0)
				continue;

			idx = rand_num(state->child_cnt);
			pid = state->child_pids[idx];

			waitpid(pid, NULL, 0);

			state->child_pids[idx] = state->child_pids[state->child_cnt - 1];
			state->child_cnt--;

			break;
		case 2: /* SLEEP */
			usleep(rand_num(env.attach_max_sleep_us));
			break;
		default: fprintf(stderr, "FORK BOOM!\n"); exit(1);
		}
	}

	for (i = 0; i < state->child_cnt; i++) {
		waitpid(state->child_pids[i], NULL, 0);
	}

	return stats;
}

static void emit_stats(struct all_stats *stats, const char *desc)
{
	printf("%s:\n"
	       "%-20s %10ld\n"
	       "%-20s %10ld\n"
	       "%-20s %10ld\n"
	       "%-20s %10ld\n"
	       "%-20s %10ld\n"
	       "%-20s %10ld\n"
	       "%-20s %10ld\n"
	       "%-20s %10ld\n",
	       desc,
	       "FUNC CALLS", stats->trig.total_calls,
	       "UPROBE HITS", stats->uprobe_hits,
	       "URETPROBE HITS", stats->uretprobe_hits,
	       "ATTACHED LINKS", stats->attach.total_links,
	       "ATTACHED UPROBES", stats->attach.total_uprobes,
	       "ATTACHED URETPROBES", stats->attach.total_uretprobes,
	       "MMAP CALLS", stats->mmap.total_mmaps,
	       "FORKS CALLS", stats->fork.total_forks);
}

static void collect_stats(struct all_stats *stats)
{
	int i;

	memset(stats, 0, sizeof(*stats));

	for (i = 0; i < env.trig_thread_cnt; i++) {
		struct trig_stats *s = env.trig_stats[i];

		stats->trig.total_calls += atomic_load(&s->total_calls);
	}
	for (i = 0; i < env.attach_thread_cnt; i++) {
		struct attach_stats *s = env.attach_stats[i];

		stats->attach.total_links += atomic_load(&s->total_links);
		stats->attach.total_uprobes += atomic_load(&s->total_uprobes);
		stats->attach.total_uretprobes += atomic_load(&s->total_uretprobes);
	}
	for (i = 0; i < env.mmap_thread_cnt; i++) {
		struct mmap_stats *s = env.mmap_stats[i];

		stats->mmap.total_mmaps += atomic_load(&s->total_mmaps);
	}
	for (i = 0; i < env.fork_thread_cnt; i++) {
		struct fork_stats *s = env.fork_stats[i];

		stats->fork.total_forks += atomic_load(&s->total_forks);
	}
	for (i = 0; i < MAX_CPUS; i++) {
		stats->uprobe_hits += atomic_load(&env.skel->bss->enter_hits[i].value);
		stats->uretprobe_hits += atomic_load(&env.skel->bss->exit_hits[i].value);
	}
}

static void *stats_thread(void *ctx)
{
	struct all_stats prev = {}, cur = {}, diff;
	unsigned long long last_ts = time_now_ns(), cur_ts;
	long period = 0;
	char buf[128];

	while (!exiting) {
		cur_ts = time_now_ns();
		if (cur_ts - last_ts < env.stats_period_ms * 1000000ULL) {
			usleep(1000);
			continue;
		}
		last_ts = cur_ts;
		period++;

		collect_stats(&cur);

		diff.trig.total_calls = cur.trig.total_calls - prev.trig.total_calls;

		diff.attach.total_links = cur.attach.total_links - prev.attach.total_links;
		diff.attach.total_uprobes = cur.attach.total_uprobes - prev.attach.total_uprobes;
		diff.attach.total_uretprobes = cur.attach.total_uretprobes - prev.attach.total_uretprobes;

		diff.mmap.total_mmaps = cur.mmap.total_mmaps - prev.mmap.total_mmaps;

		diff.fork.total_forks = cur.fork.total_forks - prev.fork.total_forks;

		diff.uprobe_hits = cur.uprobe_hits - prev.uprobe_hits;
		diff.uretprobe_hits = cur.uretprobe_hits - prev.uretprobe_hits;

		snprintf(buf, sizeof(buf), "\nPERIOD #%ld STATS", period);

		emit_stats(&diff, buf);

		prev = cur;
	}

	return NULL;
}

int main(int argc, char **argv)
{
	int i, err;
	struct all_stats stats;

	env.uprobe_fn_cnt = ARRAY_SIZE(uprobe_fns);
	srand(time(NULL));

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.child_mode) {
		unsigned long long start_ts = time_now_ns();

		while (time_now_ns() - start_ts < env.child_run_time_ms * 1000000ULL) {
			uprobe_mediator(rand_num(env.uprobe_max_depth));
		}
		return 0;
	}

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	env.skel = uprobe_stress_bpf__open_and_load();
	if (!env.skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}


	for (i = 0; i < ARRAY_SIZE(uprobe_fns); i++) {
		uprobe_offs[i] = get_uprobe_offset(uprobe_fns[i]);
		if (uprobe_offs[i] < 0) {
			fprintf(stderr, "Failed to calculate uprobe #%d offset: %ld\n", i, uprobe_offs[i]);
			exit(1);
		}
	}

	env.trig_threads = calloc(env.trig_thread_cnt, sizeof(*env.trig_threads));
	env.trig_stats = calloc(env.trig_thread_cnt, sizeof(*env.trig_stats));
	for (i = 0; i < env.trig_thread_cnt; i++) {
		err = pthread_create(&env.trig_threads[i], NULL, trig_thread, (void *)(long)i);
		if (err) {
			fprintf(stderr, "Failed to create trigger thread #%d\n", i);
			exit(1);
		}
	}

	env.attach_threads = calloc(env.attach_thread_cnt, sizeof(*env.attach_threads));
	env.attach_stats = calloc(env.attach_thread_cnt, sizeof(*env.attach_stats));
	for (i = 0; i < env.attach_thread_cnt; i++) {
		err = pthread_create(&env.attach_threads[i], NULL, attach_thread, (void *)(long)i);
		if (err) {
			fprintf(stderr, "Failed to create attach thread #%d\n", i);
			exit(1);
		}
	}

	env.mmap_threads = calloc(env.mmap_thread_cnt, sizeof(*env.mmap_threads));
	env.mmap_stats = calloc(env.mmap_thread_cnt, sizeof(*env.mmap_stats));
	for (i = 0; i < env.mmap_thread_cnt; i++) {
		err = pthread_create(&env.mmap_threads[i], NULL, mmap_thread, (void *)(long)i);
		if (err) {
			fprintf(stderr, "Failed to create mmaping thread #%d\n", i);
			exit(1);
		}
	}

	env.fork_threads = calloc(env.fork_thread_cnt, sizeof(*env.fork_threads));
	env.fork_stats = calloc(env.fork_thread_cnt, sizeof(*env.fork_stats));
	for (i = 0; i < env.fork_thread_cnt; i++) {
		err = pthread_create(&env.fork_threads[i], NULL, fork_thread, (void *)(long)i);
		if (err) {
			fprintf(stderr, "Failed to create forking thread #%d\n", i);
			exit(1);
		}
	}

	err = pthread_create(&env.stats_thread, NULL, stats_thread, NULL);
	if (err) {
		fprintf(stderr, "Failed to create stats thread\n");
		exit(1);
	}

	printf("WORKING HARD!..\n");
	while (!exiting)
		usleep(100000);
	printf("\nEXITING...\n");

	for (i = 0; i < env.trig_thread_cnt; i++) {
		pthread_join(env.trig_threads[i], NULL);
	}
	for (i = 0; i < env.attach_thread_cnt; i++) {
		pthread_join(env.attach_threads[i], NULL);
	}
	for (i = 0; i < env.mmap_thread_cnt; i++) {
		pthread_join(env.mmap_threads[i], NULL);
	}
	for (i = 0; i < env.fork_thread_cnt; i++) {
		pthread_join(env.fork_threads[i], NULL);
	}
	pthread_join(env.stats_thread, NULL);

	collect_stats(&stats);
	emit_stats(&stats, "\nFINAL STATS");

	uprobe_stress_bpf__destroy(env.skel);

	return err < 0 ? -err : 0;
}
