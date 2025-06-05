// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#define MAX_STR_LEN	128
struct cstr {
	char data[MAX_STR_LEN];
};

static __always_inline u64 cstr_pos(u64 pos)
{
	/* prevent compiler reordering comparison below with array access in cstr_char() */
	barrier_var(pos);
	/* `pos >= MAX_STR_LEN` never happens, but we need to make verifier happy */
	pos = likely(pos < MAX_STR_LEN) ? pos : 0;
	barrier_var(pos);
	return pos;
}

static __always_inline char cstr_char(const struct cstr *s, u64 pos)
{
	return s->data[cstr_pos(pos)];
}

unsigned zero = 0, one = 1; /* obfuscate integers for verifier */

static bool __substr_match(const struct cstr *haystack __arg_nonnull,
			   const struct cstr *needle __arg_nonnull,
			   int pos)
{
	u64 i;
	char c;

	bpf_for(i, 0, MAX_STR_LEN) {
		c = cstr_char(needle, i);
		if (c == '\0')
			return true;
		if (c != cstr_char(haystack, pos + i))
			return false;
	}

	return true;
}

/*
 * Find substring `needle` in a string `haystack`, starting from position
 * `start` (zero-indexed). Returns substring start position (>= `start`) if
 * match is found; negative result, otherwise.
 */
__noinline int substr_hashed(const struct cstr *haystack __arg_nonnull,
			     const struct cstr *needle __arg_nonnull,
			     int start)
{
	u32 i, need_hash = zero, hay_hash = zero, mul = one;
	int need_len = zero, hay_len = zero, p;

	bpf_for(i, 0, MAX_STR_LEN) {
		if (needle->data[i] == '\0')
			break;

		need_len += 1;
		need_hash = need_hash * 31 + (u32)needle->data[i];
		mul *= 31;
	}

	if (need_len == 0) /* emtpy substring always matches */
		return start;

	bpf_for(i, start, MAX_STR_LEN) {
		if (haystack->data[i] == '\0')
			return -1;

		hay_hash = hay_hash * 31 + (u32)haystack->data[i];
		hay_len += 1;
		if (hay_len < need_len) {
			continue;
		} else if (hay_len > need_len) {
			hay_len -= 1;
			hay_hash -= mul * cstr_char(haystack, i - hay_len);
		}

		/* now hay_len == need_len */
		p = i - (hay_len - 1);
		if (hay_hash == need_hash && __substr_match(haystack, needle, p))
			return p;
	}

	return -1;
}

__noinline int substr_naive(const struct cstr *haystack __arg_nonnull,
			    const struct cstr *needle __arg_nonnull,
			    int start)
{
	int *p;

	bpf_for_each(num, p, start, MAX_STR_LEN) {
		if (cstr_char(haystack, *p) == '\0')
			break;

		if (__substr_match(haystack, needle, *p))
			return *p;
	}

	return -1;
}

#define BENCH 0
#define BENCH_ITERS 25000

#if BENCH
static struct cstr haystack = { "abacabadabacabaeabacabadabacaba" };
static struct cstr needle = { "eaba" };
#else
static struct cstr haystack = { "abracadabra" };
static struct cstr needle = { "a" };
#endif

SEC("raw_tp/sys_enter")
int test_substr_hashed(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	int i, p;

	if (pid != my_pid)
		return 0;

#if BENCH
	u64 start, end;
	start = bpf_ktime_get_ns();
	bpf_repeat(BENCH_ITERS) {
#endif
	p = -1;
	bpf_repeat(MAX_STR_LEN) {
		p = substr_hashed(&haystack, &needle, p + 1);
		if (p < 0)
			break;
#if !BENCH
		bpf_printk("HASHED match at pos #%d!", p);
#endif
	}

#if BENCH
	}
	end = bpf_ktime_get_ns();
	bpf_printk("BENCH HASHED %lu ns/iter", (end - start) / BENCH_ITERS);
#endif
	return 0;
}

SEC("raw_tp/sys_enter")
int test_substr_naive(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	int i, p;
	u64 start, end;

	if (pid != my_pid)
		return 0;

#if BENCH
	start = bpf_ktime_get_ns();
	bpf_repeat(BENCH_ITERS) {
#endif
	p = -1;
	bpf_repeat(MAX_STR_LEN) {
		p = substr_naive(&haystack, &needle, p + 1);
		if (p < 0)
			break;
#if !BENCH
		bpf_printk("NAIVE  match at pos #%d!", p);
#endif
	}

#if BENCH
	}
	end = bpf_ktime_get_ns();
	bpf_printk("BENCH NAIVE  %lu ns/iter", (end - start) / BENCH_ITERS);
#endif

	return 0;
}
