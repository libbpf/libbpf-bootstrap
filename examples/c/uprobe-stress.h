/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __UPROBE_STRESS_H
#define __UPROBE_STRESS_H

#define CPU_MASK 255
#define MAX_CPUS (CPU_MASK + 1)

struct counter {
	long value;
} __attribute__((aligned(128)));

#endif /* __UPROBE_STRESS_H */
