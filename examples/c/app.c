#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <elf.h>
#include <pthread.h>
#include "app_lib.h"

static __thread int tls_dont_care; /* just to avoid zero offsets everywhere else */

__thread int tls_exec;
extern __thread int tls_shared;

static __thread int tls_local_exec;

int __attribute__((weak)) get_tls_exec(void)
{
	return tls_exec;
}

int __attribute__((weak)) get_tls_shared(void)
{
	return tls_shared;
}

int __attribute__((weak)) get_tls_local_exec(void)
{
	return tls_local_exec;
}

/* Forward declarations for recursive functions */
void func_a(int depth);
void func_b(int depth);
void func_c(int depth);

static __always_inline void func_mux(int depth)
{
	if (depth <= 0)
		return;

	switch (rand() % 3) {
	case 0: func_a(depth - 1); break;
	case 1: func_b(depth - 1); break;
	case 2: func_c(depth - 1); break;
	}
}

void func_a(int depth)
{
	volatile char stack_space[120];
	stack_space[119] = 'a';
	stack_space[0] += 1;

	if (depth <= 0)
		return;

	func_mux(depth - 1);
}

void func_b(int depth)
{
	volatile char stack_space[350];
	stack_space[349] = 'b';
	stack_space[0] += 1;

	if (depth <= 0)
		return;

	func_mux(depth - 1);
}

void func_c(int depth)
{
	volatile char stack_space[800];
	stack_space[799] = 'c';
	stack_space[0] += 1;

	if (depth <= 0)
		return;

	func_mux(depth - 1);
}

static void *thread_func(void *arg)
{
	time_t last_print = 0;
	(void)arg;

	pthread_setname_np(pthread_self(), "app_thread");

	while (1) {
		time_t now;

		errno = 123456789;
		func_mux(10);
		errno = 987654321;

		now = time(NULL);
		if (now > last_print) {
			tls_exec += 4;
			tls_shared += 8;
			tls_local_exec += 16;
			bump_tls_local_shared();
			bump_tls_local_shared();

			printf("Hello from thread (exec=%d, shared=%d, local_exec=%d, local_shared=%d)!\n",
				get_tls_exec(), get_tls_shared(), get_tls_local_exec(), get_tls_local_shared());
			last_print = now;
		}
	}

	return NULL;
}

int main() {
	pthread_t thread;

	pthread_create(&thread, NULL, thread_func, NULL);

	while (1) {
		tls_dont_care += 1;
		tls_exec += 2;
		tls_shared += 4;
		tls_local_exec += 8;
		bump_tls_local_shared();

		printf("Hello from app (exec=%d, shared=%d, local_exec=%d, local_shared=%d)!\n",
			get_tls_exec(), get_tls_shared(), get_tls_local_exec(), get_tls_local_shared());
		sleep(1);
	}

	return 0;
}
