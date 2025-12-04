// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "snooper.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Error codes - can't include errno.h in BPF */
#define ENOENT		2
#define EOPNOTSUPP	95
#define EPROTO		71

extern int bpf_dynptr_from_file(struct file *file, u32 flags, struct bpf_dynptr *ptr__uninit) __ksym __weak;
extern int bpf_dynptr_file_discard(struct bpf_dynptr *dynptr) __ksym __weak;

/* ========== ELF constants ========== */

#define ELFMAG0		0x7f
#define ELFMAG1		'E'
#define ELFMAG2		'L'
#define ELFMAG3		'F'

#define ELFCLASS64	2
#define EI_CLASS	4

#define SHT_SYMTAB	2
#define SHT_STRTAB	3
#define SHT_DYNSYM	11

#define STT_NOTYPE	0
#define STT_OBJECT	1
#define STT_FUNC	2
#define STT_SECTION	3
#define STT_FILE	4
#define STT_COMMON	5
#define STT_TLS		6
#define ELF64_ST_TYPE(info)	((info) & 0xf)

#define VM_EXEC		0x00000004

#define SHN_XINDEX	0xffff
#define MAX_SYM_NAME	64

struct task_state {
	struct task_event event;
	struct bpf_task_work tw;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct task_state);
} task_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} rb SEC(".maps");

struct elf_symtab {
	u32 shndx;
	u32 symtab_cnt;
	u64 symtab_off;
	u64 strtab_off;
};

struct elf {
	u64 shoff; /* section headers list offset */
	u32 shnum; /* number of sections */

	struct elf_symtab symtab, dynsym;
};

struct scratch {
	struct elf elf;

	struct elf64_hdr ehdr;
	struct elf64_shdr shdr;
	struct elf64_shdr strtab_shdr;

	struct elf64_sym sym;
	char sym_name[MAX_SYM_NAME];
};

static int zero = 0;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct scratch);
} scratch_map SEC(".maps");

/*
 * Frame pointer-based user stack unwinding.
 *
 * On x86_64 with frame pointers enabled (-fno-omit-frame-pointer):
 *   [rbp + 0]  = saved rbp (previous frame pointer)
 *   [rbp + 8]  = return address
 *
 * We walk the chain of frame pointers to collect return addresses.
 */
static int unwind_user_stack(struct task_struct *task, u64 *stack, int max_depth)
{
	struct pt_regs *regs;
	struct frame {
		u64 next_fp;    /* saved frame pointer (rbp) */
		u64 ret_addr;   /* return address */
	} frame;
	u64 fp;
	unsigned i = 0;

	regs = bpf_core_cast((void *)bpf_task_pt_regs(task), struct pt_regs);
	if (!(regs->cs & 3))
		return 0; /* not in user space mode */

	stack[0] = regs->ip;

	fp = regs->bp;
	bpf_for(i, 1, MAX_STACK_DEPTH) {
		/* read the frame, [fp] = next_fp, [fp+8] = ret_addr */
		if (bpf_copy_from_user_task(&frame, sizeof(frame), (void *)fp, task, 0))
			break;

		barrier_var(i);
		if (i < MAX_STACK_DEPTH)
			stack[i] = frame.ret_addr;

		fp = frame.next_fp;
	}

	return i * sizeof(u64);
}

static int parse_elf(struct bpf_dynptr *fdptr, struct elf *elf, struct scratch *s)
{
	int err, i;

	/* ELF header */
	err = bpf_dynptr_read(&s->ehdr, sizeof(s->ehdr), fdptr, 0, 0);
	if (err) {
		bpf_printk("  [ELF] Failed to read ELF header: %d", err);
		return err;
	}

	/* Verify ELF magic */
	if (s->ehdr.e_ident[0] != ELFMAG0 || s->ehdr.e_ident[1] != ELFMAG1 ||
	    s->ehdr.e_ident[2] != ELFMAG2 || s->ehdr.e_ident[3] != ELFMAG3) {
		bpf_printk("  [ELF] Not an ELF file");
		return -EPROTO;
	}

	/* Only support 64-bit ELF for now */
	if (s->ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
		bpf_printk("  [ELF] Not 64-bit ELF");
		return -EOPNOTSUPP;
	}

	elf->shoff = s->ehdr.e_shoff;
	elf->shnum = s->ehdr.e_shnum;

	//bpf_printk("  [ELF] Section headers: off=%llu, num=%u", elf->shoff, elf->shnum);
	if (elf->shnum == 0 || elf->shnum >= SHN_XINDEX)
		return -EOPNOTSUPP;

	elf->symtab.shndx = 0;
	elf->dynsym.shndx = 0;

	bpf_for(i, 1, elf->shnum) {
		u64 symtab_off, symtab_size, strtab_shdr_off;
		u32 symtab_entsize, strtab_idx;
		u64 shdr_off = elf->shoff + i * sizeof(struct elf64_shdr);

		err = bpf_dynptr_read(&s->shdr, sizeof(s->shdr), fdptr, shdr_off, 0);
		if (err) {
			bpf_printk("  [ELF] Failed to read shdr[%d]: %d", i, err);
			break;
		}

		if (s->shdr.sh_type != SHT_SYMTAB && s->shdr.sh_type != SHT_DYNSYM)
			continue;

		symtab_off = s->shdr.sh_offset;
		symtab_size = s->shdr.sh_size;
		symtab_entsize = s->shdr.sh_entsize ?: sizeof(struct elf64_sym);

		/* sh_link points to the associated string table */
		strtab_idx = s->shdr.sh_link;
		strtab_shdr_off = elf->shoff + strtab_idx * sizeof(struct elf64_shdr);
		err = bpf_dynptr_read(&s->strtab_shdr, sizeof(s->strtab_shdr), fdptr, strtab_shdr_off, 0);
		if (err) {
			bpf_printk("  [ELF] Failed to read strtab shdr[%d]: %d", strtab_idx, err);
			return err;
		}

		//bpf_printk("  [ELF] Found %s: off=%llu, cnt=%llu",
		//	   s->shdr.sh_type == SHT_SYMTAB ? ".symtab" : ".dynsym",
		//	   symtab_off, symtab_size / symtab_entsize);

		if (s->shdr.sh_type == SHT_SYMTAB) {
			elf->symtab.shndx = i;
			elf->symtab.symtab_off = symtab_off;
			elf->symtab.symtab_cnt = symtab_size / symtab_entsize;
			elf->symtab.strtab_off = s->strtab_shdr.sh_offset;
		} else {
			elf->dynsym.shndx = i;
			elf->dynsym.symtab_off = symtab_off;
			elf->dynsym.symtab_cnt = symtab_size / symtab_entsize;
			elf->dynsym.strtab_off = s->strtab_shdr.sh_offset;
		}

		if (elf->dynsym.shndx && elf->symtab.shndx)
			break;
	}

	return 0;
}

static const char *sym_type_str(u8 type)
{
	switch (type) {
	case STT_NOTYPE:  return "NOTYPE";
	case STT_OBJECT:  return "OBJECT";
	case STT_FUNC:    return "FUNC";
	case STT_SECTION: return "SECTION";
	case STT_FILE:    return "FILE";
	case STT_COMMON:  return "COMMON";
	case STT_TLS:     return "TLS";
	default:          return "UNKNOWN";
	}
}

static int find_sym(struct bpf_dynptr *fdptr, struct elf_symtab *symtab,
		    const char *sym_name, int sym_type,
		    struct scratch *s)
{
	int err, i, j;

	if (!symtab->shndx)
		return -ENOENT;

	bpf_for(i, 1, symtab->symtab_cnt) {
		u64 sym_off = symtab->symtab_off + i * sizeof(struct elf64_sym);
		u8 type;
		bool match;

		err = bpf_dynptr_read(&s->sym, sizeof(s->sym), fdptr, sym_off, 0);
		if (err)
			return err;

		/* skip anonymous or external symbols */
		if (s->sym.st_name == 0 || s->sym.st_shndx == 0)
			continue;

		type = ELF64_ST_TYPE(s->sym.st_info);
		if (sym_type && type != sym_type)
			continue;

		err = bpf_dynptr_read(s->sym_name, sizeof(s->sym_name), fdptr,
				      symtab->strtab_off + s->sym.st_name, 0);
		if (err)
			return err;
		s->sym_name[sizeof(s->sym_name) - 1] = '\0';

		if (bpf_strcmp(s->sym_name, sym_name) != 0)
			continue;

		return i;
	}

	return -ENOENT;
}

/*
 * Iterate symbols from a symbol table and print all symbols.
 */
static void print_symtab(struct bpf_dynptr *fdptr, struct elf_symtab *symtab,
			 const char *name, struct scratch *s)
{
	int err, i;

	if (!symtab->shndx)
		return;

	bpf_printk("  [ELF] Parsing %s (%u symbols):", name, symtab->symtab_cnt);
	bpf_for(i, 1, symtab->symtab_cnt) {
		u64 sym_off = symtab->symtab_off + i * sizeof(struct elf64_sym);
		u8 sym_type;

		err = bpf_dynptr_read(&s->sym, sizeof(s->sym), fdptr, sym_off, 0);
		if (err)
			break;

		if (s->sym.st_name == 0)
			continue;

		/* Skip undefined symbols (external references) */
		if (s->sym.st_shndx == 0)
			continue;

		err = bpf_dynptr_read(s->sym_name, sizeof(s->sym_name), fdptr,
				      symtab->strtab_off + s->sym.st_name, 0);
		if (err) {
			bpf_printk("    [SYM] Failed to read symbol #%d: %d\n", i, err);
			break;
		}
		s->sym_name[sizeof(s->sym_name) - 1] = '\0';

		sym_type = ELF64_ST_TYPE(s->sym.st_info);

		bpf_printk("    [SYM] 0x%llx %s %s", s->sym.st_value, sym_type_str(sym_type), s->sym_name);
	}
}

/*
 * Parse ELF file and print all symbols using bpf_printk.
 */
static void parse_elf_symbols(struct bpf_dynptr *fdptr, struct elf *elf, struct scratch *s)
{
	print_symtab(fdptr, &elf->symtab, ".symtab", s);
	print_symtab(fdptr, &elf->dynsym, ".dynsym", s);
}

int MINUS_ONE = -1;

/*
 * Iterate VMAs of the current task, find executable file-backed VMAs,
 * and parse their ELF symbols.
 */
static int enumerate_vmas(struct task_struct *task)
{
	struct vm_area_struct *vma;
	struct scratch *s;
	u64 last_ino = MINUS_ONE;
	int err;

	s = bpf_map_lookup_elem(&scratch_map, &zero);
	if (!s)
		return 0; /* can't happen */

	bpf_printk("[VMA] Enumerating VMAs for task %d (%s)", task->pid, task->comm);

	bpf_for_each(task_vma, vma, task, 0) {
		struct bpf_dynptr fdptr;
		struct inode *inode;
		struct file *file;

		if (!(vma->vm_flags & VM_EXEC))
			continue;

		file = vma->vm_file;
		if (!file)
			continue;
		inode = file->f_inode;
		if (!inode)
			continue;

		/*
		 * This is a cheap and effective way to minimize reparsing of the same ELF, but
		 * it doesn't guarantee that each unique inode will be processed just once. This
		 * is acceptable for an example, though.
		 */
		u64 ino = inode->i_ino;
		if (last_ino == ino)
			continue;

		const char *vma_name = (const char *)file->f_path.dentry->d_name.name;
		bpf_printk("[VMA] Executable file-backed VMA: 0x%lx-0x%lx (ino=%llu, name=%s)",
			   vma->vm_start, vma->vm_end, ino, vma_name);


		err = bpf_dynptr_from_file(file, 0, &fdptr);
		if (err) {
			bpf_printk("  [ELF] Failed to create dynptr for (ino=%llu, name=%s): %d", ino, vma_name, err);
			goto next;
		}

		err = parse_elf(&fdptr, &s->elf, s);
		if (err)
			goto next;

		//parse_elf_symbols(&fdptr, &s->elf, s);

		if (task->pid != task->tgid)
			goto next;

		int sym_idx = find_sym(&fdptr, &s->elf.dynsym, "tls_shared", STT_TLS, s);
		if (sym_idx > 0) {
			bpf_printk("FOUND TLS SYM '%s' in .dynsym for '%s': st_value=%llx sz=%llu, shndx=%u\n",
				   s->sym_name, vma_name,
				   s->sym.st_value, s->sym.st_size, s->sym.st_shndx);
			goto next;
		}
		sym_idx = find_sym(&fdptr, &s->elf.symtab, "tls_shared", STT_TLS, s);
		if (sym_idx > 0) {
			bpf_printk("FOUND TLS SYM '%s' in .symtab for '%s': st_value=%llx sz=%llu, shndx=%u\n",
				   s->sym_name, vma_name,
				   s->sym.st_value, s->sym.st_size, s->sym.st_shndx);
		}

next:
		bpf_dynptr_file_discard(&fdptr);

		last_ino = ino;
	}

	return 0;
}

static int task_work_cb(struct bpf_map *map, void *key, void *value)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct task_state *state = value;
	struct task_event *event = &state->event;
	u32 tid = task->pid;

	if (event->tid != task->pid) {
		bpf_printk("MISMATCHED PID %d != expected %d", task->pid, event->tid);
		goto cleanup;
	}

	event->ustack_sz = unwind_user_stack(task, event->ustack, MAX_STACK_DEPTH);

	enumerate_vmas(task);

	bpf_ringbuf_output(&rb, event, sizeof(*event), 0);
cleanup:
	bpf_map_delete_elem(&task_states, key);
	return 0;
}

/*
 * THIS DOESN'T CURRENTLY WORK:
 * static struct task_state empty_state;
 *
 * Verifier will complain:
 * bpf_task_work cannot be accessed directly by load/store
 */
static char empty_state[sizeof(struct task_state)];

SEC("iter.s/task")
int snoop_tasks(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_state *state;
	struct task_event *event;
	u32 tid;
	int err;

	if (!task)
		return 0;

	tid = task->pid;

	err = bpf_map_update_elem(&task_states, &tid, &empty_state, BPF_NOEXIST);
	if (err) {
		bpf_printk("Unexpected error adding task state for %d (%s): %d", tid, task->comm, err);
		return 0;
	}
	state = bpf_map_lookup_elem(&task_states, &tid);
	if (!state) {
		bpf_printk("Unexpected error fetching task state for %d (%s): %d", tid, task->comm, err);
		return 0;
	}

	event = &state->event;
	event->pid = task->tgid;
	event->tid = task->pid;
	bpf_probe_read_kernel_str(event->comm, TASK_COMM_LEN, task->comm);

	event->kstack_sz = bpf_get_task_stack(task, event->kstack, sizeof(event->kstack), 0);

	err = bpf_task_work_schedule_signal_impl(task, &state->tw, &task_states, task_work_cb, NULL);
	if (err) {
		bpf_printk("Unexpected error scheduling task work %d (%s): %d", tid, task->comm, err);
		bpf_map_delete_elem(&task_states, &tid);
		return 0;
	}

	return 0;
}
