#define _POSIX_C_SOURCE 200809L
#include <argp.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "smbvfsslower.h"
#include "smbvfsslower.skel.h"

#define PERF_BUFFER_PAGES    64
#define PERF_POLL_TIMEOUT_MS 100
#define NSEC_PER_SEC	     1000000000LL

#define warn(...)	     fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

/* Callback categories */
enum callback_category {
	CATEGORY_FILE,
	CATEGORY_INODE,
	CATEGORY_ADSPACE,
	CATEGORY_SUPER,
};

/* Callback registry entry */
struct callback_info {
	const char *name;
	enum callback_category category;
	const char *entry_prog;  /* BPF program name for entry */
	const char *exit_prog;   /* BPF program name for exit */
};

/* Global callback registry - add new callbacks here */
static const struct callback_info callback_registry[] = {
	/* File operations */
	{ "cifs_loose_read_iter", CATEGORY_FILE, "trace_file_loose_read_iter_entry", "trace_file_loose_read_iter_exit" },
	{ "cifs_file_write_iter", CATEGORY_FILE, "trace_file_file_write_iter_entry", "trace_file_file_write_iter_exit" },
	{ "cifs_open", CATEGORY_FILE, "trace_file_open_entry", "trace_file_open_exit" },
	{ "cifs_close", CATEGORY_FILE, "trace_file_close_entry", "trace_file_close_exit" },
	{ "cifs_lock", CATEGORY_FILE, "trace_file_lock_entry", "trace_file_lock_exit" },
	{ "cifs_flock", CATEGORY_FILE, "trace_file_flock_entry", "trace_file_flock_exit" },
	{ "cifs_fsync", CATEGORY_FILE, "trace_file_fsync_entry", "trace_file_fsync_exit" },
	{ "cifs_flush", CATEGORY_FILE, "trace_file_flush_entry", "trace_file_flush_exit" },
	{ "cifs_file_mmap", CATEGORY_FILE, "trace_file_file_mmap_entry", "trace_file_file_mmap_exit" },
	{ "filemap_splice_read", CATEGORY_FILE, "trace_file_filemap_splice_read_entry", "trace_file_filemap_splice_read_exit" },
	{ "iter_file_splice_write", CATEGORY_FILE, "trace_file_iter_file_splice_write_entry", "trace_file_iter_file_splice_write_exit" },
	{ "cifs_llseek", CATEGORY_FILE, "trace_file_llseek_entry", "trace_file_llseek_exit" },
	{ "cifs_ioctl", CATEGORY_FILE, "trace_file_ioctl_entry", "trace_file_ioctl_exit" },
	{ "cifs_copy_file_range", CATEGORY_FILE, "trace_file_copy_file_range_entry", "trace_file_copy_file_range_exit" },
	{ "cifs_remap_file_range", CATEGORY_FILE, "trace_file_remap_file_range_entry", "trace_file_remap_file_range_exit" },
	{ "cifs_setlease", CATEGORY_FILE, "trace_file_setlease_entry", "trace_file_setlease_exit" },
	{ "cifs_fallocate", CATEGORY_FILE, "trace_file_fallocate_entry", "trace_file_fallocate_exit" },
	{ "cifs_strict_readv", CATEGORY_FILE, "trace_file_strict_readv_entry", "trace_file_strict_readv_exit" },
	{ "cifs_strict_writev", CATEGORY_FILE, "trace_file_strict_writev_entry", "trace_file_strict_writev_exit" },
	{ "cifs_strict_fsync", CATEGORY_FILE, "trace_file_strict_fsync_entry", "trace_file_strict_fsync_exit" },
	{ "cifs_file_strict_mmap", CATEGORY_FILE, "trace_file_file_strict_mmap_entry", "trace_file_file_strict_mmap_exit" },
	{ "cifs_direct_readv", CATEGORY_FILE, "trace_file_direct_readv_entry", "trace_file_direct_readv_exit" },
	{ "cifs_direct_writev", CATEGORY_FILE, "trace_file_direct_writev_entry", "trace_file_direct_writev_exit" },
	{ "copy_splice_read", CATEGORY_FILE, "trace_file_copy_splice_read_entry", "trace_file_copy_splice_read_exit" },
	{ "cifs_readdir", CATEGORY_FILE, "trace_file_readdir_entry", "trace_file_readdir_exit" },
	{ "cifs_closedir", CATEGORY_FILE, "trace_file_closedir_entry", "trace_file_closedir_exit" },
	{ "generic_read_dir", CATEGORY_FILE, "trace_file_generic_read_dir_entry", "trace_file_generic_read_dir_exit" },
	{ "generic_file_llseek", CATEGORY_FILE, "trace_file_generic_file_llseek_entry", "trace_file_generic_file_llseek_exit" },
	{ "cifs_dir_fsync", CATEGORY_FILE, "trace_file_dir_fsync_entry", "trace_file_dir_fsync_exit" },

	/* Inode operations */
	{ "cifs_create", CATEGORY_INODE, "trace_inode_create_entry", "trace_inode_create_exit" },
	{ "cifs_atomic_open", CATEGORY_INODE, "trace_inode_atomic_open_entry", "trace_inode_atomic_open_exit" },
	{ "cifs_lookup", CATEGORY_INODE, "trace_inode_lookup_entry", "trace_inode_lookup_exit" },
	{ "cifs_getattr", CATEGORY_INODE, "trace_inode_getattr_entry", "trace_inode_getattr_exit" },
	{ "cifs_unlink", CATEGORY_INODE, "trace_inode_unlink_entry", "trace_inode_unlink_exit" },
	{ "cifs_hardlink", CATEGORY_INODE, "trace_inode_hardlink_entry", "trace_inode_hardlink_exit" },
	{ "cifs_mkdir", CATEGORY_INODE, "trace_inode_mkdir_entry", "trace_inode_mkdir_exit" },
	{ "cifs_rmdir", CATEGORY_INODE, "trace_inode_rmdir_entry", "trace_inode_rmdir_exit" },
	{ "cifs_rename2", CATEGORY_INODE, "trace_inode_rename2_entry", "trace_inode_rename2_exit" },
	{ "cifs_permission", CATEGORY_INODE, "trace_inode_permission_entry", "trace_inode_permission_exit" },
	{ "cifs_setattr", CATEGORY_INODE, "trace_inode_setattr_entry", "trace_inode_setattr_exit" },
	{ "cifs_symlink", CATEGORY_INODE, "trace_inode_symlink_entry", "trace_inode_symlink_exit" },
	{ "cifs_mknod", CATEGORY_INODE, "trace_inode_mknod_entry", "trace_inode_mknod_exit" },
	{ "cifs_listxattr", CATEGORY_INODE, "trace_inode_listxattr_entry", "trace_inode_listxattr_exit" },
	{ "cifs_get_acl", CATEGORY_INODE, "trace_inode_get_acl_entry", "trace_inode_get_acl_exit" },
	{ "cifs_set_acl", CATEGORY_INODE, "trace_inode_set_acl_entry", "trace_inode_set_acl_exit" },
	{ "cifs_fiemap", CATEGORY_INODE, "trace_inode_fiemap_entry", "trace_inode_fiemap_exit" },
	{ "cifs_get_link", CATEGORY_INODE, "trace_inode_get_link_entry", "trace_inode_get_link_exit" },

	/* Address space operations */
	{ "cifs_read_folio", CATEGORY_ADSPACE, "trace_adspace_read_folio_entry", "trace_adspace_read_folio_exit" },
	{ "cifs_readahead", CATEGORY_ADSPACE, "trace_adspace_readahead_entry", "trace_adspace_readahead_exit" },
	{ "cifs_writepages", CATEGORY_ADSPACE, "trace_adspace_writepages_entry", "trace_adspace_writepages_exit" },
	{ "cifs_write_begin", CATEGORY_ADSPACE, "trace_adspace_write_begin_entry", "trace_adspace_write_begin_exit" },
	{ "cifs_write_end", CATEGORY_ADSPACE, "trace_adspace_write_end_entry", "trace_adspace_write_end_exit" },
	{ "netfs_dirty_folio", CATEGORY_ADSPACE, "trace_adspace_dirty_folio_entry", "trace_adspace_dirty_folio_exit" },
	{ "cifs_release_folio", CATEGORY_ADSPACE, "trace_adspace_release_folio_entry", "trace_adspace_release_folio_exit" },
	{ "cifs_direct_io", CATEGORY_ADSPACE, "trace_adspace_direct_io_entry", "trace_adspace_direct_io_exit" },
	{ "cifs_invalidate_folio", CATEGORY_ADSPACE, "trace_adspace_invalidate_folio_entry", "trace_adspace_invalidate_folio_exit" },
	{ "cifs_launder_folio", CATEGORY_ADSPACE, "trace_adspace_launder_folio_entry", "trace_adspace_launder_folio_exit" },
	{ "filemap_migrate_folio", CATEGORY_ADSPACE, "trace_adspace_migrate_folio_entry", "trace_adspace_migrate_folio_exit" },
	{ "cifs_swap_activate", CATEGORY_ADSPACE, "trace_adspace_swap_activate_entry", "trace_adspace_swap_activate_exit" },
	{ "cifs_swap_deactivate", CATEGORY_ADSPACE, "trace_adspace_swap_deactivate_entry", "trace_adspace_swap_deactivate_exit" },

	/* Superblock operations */
	{ "cifs_statfs", CATEGORY_SUPER, "trace_super_statfs_entry", "trace_super_statfs_exit" },
	{ "cifs_alloc_inode", CATEGORY_SUPER, "trace_super_alloc_inode_entry", "trace_super_alloc_inode_exit" },
	{ "cifs_write_inode", CATEGORY_SUPER, "trace_super_write_inode_entry", "trace_super_write_inode_exit" },
	{ "cifs_free_inode", CATEGORY_SUPER, "trace_super_free_inode_entry", "trace_super_free_inode_exit" },
	{ "cifs_drop_inode", CATEGORY_SUPER, "trace_super_drop_inode_entry", "trace_super_drop_inode_exit" },
	{ "cifs_evict_inode", CATEGORY_SUPER, "trace_super_evict_inode_entry", "trace_super_evict_inode_exit" },
	{ "cifs_show_devname", CATEGORY_SUPER, "trace_super_show_devname_entry", "trace_super_show_devname_exit" },
	{ "cifs_show_options", CATEGORY_SUPER, "trace_super_show_options_entry", "trace_super_show_options_exit" },
	{ "cifs_umount_begin", CATEGORY_SUPER, "trace_super_umount_begin_entry", "trace_super_umount_begin_exit" },
	{ "cifs_freeze", CATEGORY_SUPER, "trace_super_freeze_entry", "trace_super_freeze_exit" },
};

#define NUM_CALLBACKS (sizeof(callback_registry) / sizeof(callback_registry[0]))

static const char *category_names[] = {
	[CATEGORY_FILE] = "FILE OPERATIONS",
	[CATEGORY_INODE] = "INODE OPERATIONS",
	[CATEGORY_ADSPACE] = "ADDRESS SPACE OPERATIONS",
	[CATEGORY_SUPER] = "SUPERBLOCK OPERATIONS",
};

/* Callback tracking */
#define MAX_CALLBACKS 256
static char *selected_callbacks[MAX_CALLBACKS];
static int num_selected_callbacks = 0;

/* options */
static pid_t target_pid = 0;
static time_t duration = 0;
static bool inode_ops = false;
static bool file_ops = false;
static bool adspace_ops = false;
static bool super_ops = false;
static __u64 min_lat_ms = 10;
static bool csv = false;
static bool verbose = false;
static bool list_callbacks = false;

const char *argp_program_version = "smbvfsslower 0.1";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
	"Trace slow VFS callbacks for SMB operations.\n"
	"\n"
	"Usage: smbvfsslower [-h] [-p PID] [-m MIN] [-d DURATION] [-j] [--inode] [--adspace] [--super] [--file] [--callback NAME]\n"
	"\n"
	"EXAMPLES:\n"
	"    smbvfsslower 		               				# trace smb vfs callbacks slower than 10 ms\n"
	"    smbvfsslower -p 1216			   				# trace smb vfs callbacks with PID 1216 only\n"
	"    smbvfsslower -d 1 -j --inode --super		    # trace smb vfs callbacks for 1s with csv output, inode and superblock ops only\n"
	"    smbvfsslower --callback cifs_open --callback cifs_read  # trace only open and read callbacks\n"
	"    smbvfsslower --list							# list all available VFS callbacks\n";

static const struct argp_option opts[] = {
	{ "csv", 'j', NULL, 0, "Output as csv" },
	{ "inode", 'i', NULL, 0, "Trace inode ops" },
	{ "file", 'f', NULL, 0, "Trace file ops" },
	{ "super", 's', NULL, 0, "Trace superblock ops" },
	{ "adspace", 'a', NULL, 0, "Trace address space ops" },
	{ "duration", 'd', "DURATION", 0, "Total duration of trace in seconds" },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "min", 'm', "MIN", 0, "Min latency to trace, in ms (default 10)" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "callback", 'c', "CALLBACK", 0, "Trace specific VFS callback (can be specified multiple times)" },
	{ "list", 'l', NULL, 0, "List all available VFS callbacks" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		verbose = true;
		break;
	case 'j':
		csv = true;
		break;
	case 'i':
		inode_ops = true;
		break;
	case 'f':
		file_ops = true;
		break;
	case 'a':
		adspace_ops = true;
		break;
	case 's':
		super_ops = true;
		break;
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0) {
			warn("invalid DURATION: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
		errno = 0;
		min_lat_ms = strtoll(arg, NULL, 10);
		if (errno || min_lat_ms < 0) {
			warn("invalid latency (in ms): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'p':
		errno = 0;
		target_pid = strtol(arg, NULL, 10);
		if (errno || target_pid <= 0) {
			warn("invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		if (num_selected_callbacks >= MAX_CALLBACKS) {
			warn("Too many callbacks specified (max %d)\n", MAX_CALLBACKS);
			return ARGP_ERR_UNKNOWN;
		}
		selected_callbacks[num_selected_callbacks++] = strdup(arg);
		break;
	case 'l':
		list_callbacks = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void list_all_callbacks(void)
{
	printf("Available VFS callbacks:\n\n");

	enum callback_category last_category = -1;
	int callbacks_in_line = 0;

	for (size_t i = 0; i < NUM_CALLBACKS; i++) {
		const struct callback_info *cb = &callback_registry[i];

		/* Print category header when category changes */
		if (cb->category != last_category) {
			if (last_category != -1)
				printf("\n");  /* End previous category */

			printf("\n%s:\n  ", category_names[cb->category]);
			callbacks_in_line = 0;
			last_category = cb->category;
		}

		/* Print callback name */
		printf("%s", cb->name);
		callbacks_in_line++;

		/* Add separator or newline for formatting */
		if (i + 1 < NUM_CALLBACKS && callback_registry[i + 1].category == cb->category) {
			printf(", ");
			/* Wrap to next line after ~5 callbacks for readability */
			if (callbacks_in_line >= 5) {
				printf("\n  ");
				callbacks_in_line = 0;
			}
		}
	}

	printf("\n\nUsage: smbvfsslower --callback <name> [--callback <name> ...]\n");
}

static void sig_int(int signo)
{
	exiting = 1;
}

/* Helper function to attach a specific callback by name */
static int attach_specific_callback(struct smbvfsslower_bpf *obj, const char *callback_name)
{
	/* Find callback in registry */
	const struct callback_info *cb = NULL;
	for (size_t i = 0; i < NUM_CALLBACKS; i++) {
		if (strcmp(callback_registry[i].name, callback_name) == 0) {
			cb = &callback_registry[i];
			break;
		}
	}

	if (!cb) {
		warn("Unknown callback: %s\n", callback_name);
		warn("Use --list to see available callbacks\n");
		return -1;
	}

	/* Attach entry and exit programs using program names from registry */
	int err = 0;
	struct bpf_program *entry_prog = bpf_object__find_program_by_name(obj->obj, cb->entry_prog);
	struct bpf_program *exit_prog = bpf_object__find_program_by_name(obj->obj, cb->exit_prog);

	if (!entry_prog || !exit_prog) {
		warn("Failed to find BPF programs for callback %s\n", callback_name);
		return -1;
	}

	/* Enable the programs for autoload */
	bpf_program__set_autoload(entry_prog, true);
	bpf_program__set_autoload(exit_prog, true);

	err = bpf_program__set_attach_target(entry_prog, 0, callback_name);
	if (err) {
		warn("Failed to set attach target for %s entry: %d\n", callback_name, err);
		return err;
	}

	err = bpf_program__set_attach_target(exit_prog, 0, callback_name);
	if (err) {
		warn("Failed to set attach target for %s exit: %d\n", callback_name, err);
		return err;
	}

	return 0;
}

static int file_fentry_set_attach_target(struct smbvfsslower_bpf *obj)
{
	int err = 0;
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_loose_read_iter_entry, 0,
						     "cifs_loose_read_iter");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_loose_read_iter_exit, 0,
						     "cifs_loose_read_iter");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_file_write_iter_entry, 0,
						     "cifs_file_write_iter");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_file_write_iter_exit, 0,
						     "cifs_file_write_iter");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_open_entry, 0,
						     "cifs_open");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_open_exit, 0,
						     "cifs_open");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_close_entry, 0,
						     "cifs_close");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_close_exit, 0,
						     "cifs_close");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_lock_entry, 0,
						     "cifs_lock");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_lock_exit, 0,
						     "cifs_lock");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_flock_entry, 0,
						     "cifs_flock");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_flock_exit, 0,
						     "cifs_flock");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_fsync_entry, 0,
						     "cifs_fsync");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_fsync_exit, 0,
						     "cifs_fsync");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_flush_entry, 0,
						     "cifs_flush");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_flush_exit, 0,
						     "cifs_flush");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_file_mmap_entry, 0,
						     "cifs_file_mmap");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_file_mmap_exit, 0,
						     "cifs_file_mmap");

	err = err   ?:
		      bpf_program__set_attach_target(
			      obj->progs.trace_file_filemap_splice_read_entry, 0,
			      "filemap_splice_read");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_filemap_splice_read_exit,
						     0, "filemap_splice_read");

	err = err   ?:
		      bpf_program__set_attach_target(
			      obj->progs.trace_file_iter_file_splice_write_entry, 0,
			      "iter_file_splice_write");
	err = err   ?:
		      bpf_program__set_attach_target(
			      obj->progs.trace_file_iter_file_splice_write_exit, 0,
			      "iter_file_splice_write");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_llseek_entry, 0,
						     "cifs_llseek");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_llseek_exit, 0,
						     "cifs_llseek");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_ioctl_entry, 0,
						     "cifs_ioctl");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_ioctl_exit, 0,
						     "cifs_ioctl");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_copy_file_range_entry, 0,
						     "cifs_copy_file_range");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_copy_file_range_exit, 0,
						     "cifs_copy_file_range");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_remap_file_range_entry,
						     0, "cifs_remap_file_range");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_remap_file_range_exit, 0,
						     "cifs_remap_file_range");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_setlease_entry, 0,
						     "cifs_setlease");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_setlease_exit, 0,
						     "cifs_setlease");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_fallocate_entry, 0,
						     "cifs_fallocate");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_fallocate_exit, 0,
						     "cifs_fallocate");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_strict_readv_entry, 0,
						     "cifs_strict_readv");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_strict_readv_exit, 0,
						     "cifs_strict_readv");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_strict_writev_entry, 0,
						     "cifs_strict_writev");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_strict_writev_exit, 0,
						     "cifs_strict_writev");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_strict_fsync_entry, 0,
						     "cifs_strict_fsync");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_strict_fsync_exit, 0,
						     "cifs_strict_fsync");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_file_strict_mmap_entry,
						     0, "cifs_file_strict_mmap");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_file_strict_mmap_exit, 0,
						     "cifs_file_strict_mmap");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_direct_readv_entry, 0,
						     "cifs_direct_readv");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_direct_readv_exit, 0,
						     "cifs_direct_readv");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_direct_writev_entry, 0,
						     "cifs_direct_writev");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_direct_writev_exit, 0,
						     "cifs_direct_writev");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_copy_splice_read_entry,
						     0, "copy_splice_read");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_copy_splice_read_exit, 0,
						     "copy_splice_read");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_readdir_entry, 0,
						     "cifs_readdir");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_readdir_exit, 0,
						     "cifs_readdir");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_closedir_entry, 0,
						     "cifs_closedir");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_closedir_exit, 0,
						     "cifs_closedir");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_generic_read_dir_entry,
						     0, "generic_read_dir");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_generic_read_dir_exit, 0,
						     "generic_read_dir");

	err = err   ?:
		      bpf_program__set_attach_target(
			      obj->progs.trace_file_generic_file_llseek_entry, 0,
			      "generic_file_llseek");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_generic_file_llseek_exit,
						     0, "generic_file_llseek");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_dir_fsync_entry, 0,
						     "cifs_dir_fsync");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_dir_fsync_exit, 0,
						     "cifs_dir_fsync");

	return err;
}

static void file_fentry_disable_target(struct smbvfsslower_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.trace_file_loose_read_iter_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_loose_read_iter_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_file_write_iter_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_file_write_iter_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_open_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_open_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_close_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_close_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_lock_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_lock_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_flock_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_flock_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_fsync_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_fsync_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_flush_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_flush_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_file_mmap_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_file_mmap_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_filemap_splice_read_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_filemap_splice_read_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_iter_file_splice_write_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_iter_file_splice_write_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_llseek_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_llseek_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_ioctl_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_ioctl_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_copy_file_range_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_copy_file_range_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_remap_file_range_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_remap_file_range_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_setlease_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_setlease_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_fallocate_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_fallocate_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_strict_readv_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_strict_readv_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_strict_writev_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_strict_writev_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_strict_fsync_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_strict_fsync_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_file_strict_mmap_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_file_strict_mmap_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_direct_readv_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_direct_readv_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_direct_writev_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_direct_writev_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_copy_splice_read_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_copy_splice_read_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_readdir_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_readdir_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_closedir_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_closedir_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_generic_read_dir_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_generic_read_dir_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_generic_file_llseek_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_generic_file_llseek_exit, false);

	bpf_program__set_autoload(obj->progs.trace_file_dir_fsync_entry, false);
	bpf_program__set_autoload(obj->progs.trace_file_dir_fsync_exit, false);
}

static int inode_fentry_set_attach_target(struct smbvfsslower_bpf *obj)
{
	int err = 0;
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_create_entry, 0,
						     "cifs_create");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_create_exit, 0,
						     "cifs_create");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_atomic_open_entry, 0,
						     "cifs_atomic_open");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_atomic_open_exit, 0,
						     "cifs_atomic_open");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_lookup_entry, 0,
						     "cifs_lookup");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_lookup_exit, 0,
						     "cifs_lookup");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_getattr_entry, 0,
						     "cifs_getattr");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_getattr_exit, 0,
						     "cifs_getattr");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_unlink_entry, 0,
						     "cifs_unlink");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_unlink_exit, 0,
						     "cifs_unlink");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_hardlink_entry, 0,
						     "cifs_hardlink");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_hardlink_exit, 0,
						     "cifs_hardlink");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_mkdir_entry, 0,
						     "cifs_mkdir");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_mkdir_exit, 0,
						     "cifs_mkdir");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_rmdir_entry, 0,
						     "cifs_rmdir");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_rmdir_exit, 0,
						     "cifs_rmdir");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_rename2_entry, 0,
						     "cifs_rename2");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_rename2_exit, 0,
						     "cifs_rename2");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_permission_entry, 0,
						     "cifs_permission");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_permission_exit, 0,
						     "cifs_permission");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_setattr_entry, 0,
						     "cifs_setattr");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_setattr_exit, 0,
						     "cifs_setattr");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_symlink_entry, 0,
						     "cifs_symlink");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_symlink_exit, 0,
						     "cifs_symlink");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_mknod_entry, 0,
						     "cifs_mknod");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_mknod_exit, 0,
						     "cifs_mknod");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_listxattr_entry, 0,
						     "cifs_listxattr");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_listxattr_exit, 0,
						     "cifs_listxattr");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_get_acl_entry, 0,
						     "cifs_get_acl");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_get_acl_exit, 0,
						     "cifs_get_acl");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_set_acl_entry, 0,
						     "cifs_set_acl");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_set_acl_exit, 0,
						     "cifs_set_acl");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_fiemap_entry, 0,
						     "cifs_fiemap");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_fiemap_exit, 0,
						     "cifs_fiemap");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_get_link_entry, 0,
						     "cifs_get_link");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_get_link_exit, 0,
						     "cifs_get_link");

	return err;
}

static void inode_fentry_disable_attach_target(struct smbvfsslower_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.trace_inode_create_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_create_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_atomic_open_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_atomic_open_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_lookup_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_lookup_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_getattr_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_getattr_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_unlink_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_unlink_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_hardlink_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_hardlink_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_mkdir_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_mkdir_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_rmdir_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_rmdir_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_rename2_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_rename2_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_permission_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_permission_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_setattr_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_setattr_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_symlink_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_symlink_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_mknod_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_mknod_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_listxattr_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_listxattr_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_get_acl_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_get_acl_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_set_acl_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_set_acl_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_fiemap_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_fiemap_exit, false);

	bpf_program__set_autoload(obj->progs.trace_inode_get_link_entry, false);
	bpf_program__set_autoload(obj->progs.trace_inode_get_link_exit, false);
}

static int super_fentry_set_attach_target(struct smbvfsslower_bpf *obj)
{
	int err = 0;
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_statfs_entry, 0,
						     "cifs_statfs");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_statfs_exit, 0,
						     "cifs_statfs");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_alloc_inode_entry, 0,
						     "cifs_alloc_inode");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_alloc_inode_exit, 0,
						     "cifs_alloc_inode");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_write_inode_entry, 0,
						     "cifs_write_inode");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_write_inode_exit, 0,
						     "cifs_write_inode");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_free_inode_entry, 0,
						     "cifs_free_inode");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_free_inode_exit, 0,
						     "cifs_free_inode");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_drop_inode_entry, 0,
						     "cifs_drop_inode");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_drop_inode_exit, 0,
						     "cifs_drop_inode");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_evict_inode_entry, 0,
						     "cifs_evict_inode");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_evict_inode_exit, 0,
						     "cifs_evict_inode");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_show_devname_entry, 0,
						     "cifs_show_devname");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_show_devname_exit, 0,
						     "cifs_show_devname");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_show_options_entry, 0,
						     "cifs_show_options");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_show_options_exit, 0,
						     "cifs_show_options");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_umount_begin_entry, 0,
						     "cifs_umount_begin");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_umount_begin_exit, 0,
						     "cifs_umount_begin");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_freeze_entry, 0,
						     "cifs_freeze");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_freeze_exit, 0,
						     "cifs_freeze");
	return err;
}

static void super_fentry_disable_target(struct smbvfsslower_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.trace_super_statfs_entry, false);
	bpf_program__set_autoload(obj->progs.trace_super_statfs_exit, false);

	bpf_program__set_autoload(obj->progs.trace_super_alloc_inode_entry, false);
	bpf_program__set_autoload(obj->progs.trace_super_alloc_inode_exit, false);

	bpf_program__set_autoload(obj->progs.trace_super_write_inode_entry, false);
	bpf_program__set_autoload(obj->progs.trace_super_write_inode_exit, false);

	bpf_program__set_autoload(obj->progs.trace_super_free_inode_entry, false);
	bpf_program__set_autoload(obj->progs.trace_super_free_inode_exit, false);

	bpf_program__set_autoload(obj->progs.trace_super_drop_inode_entry, false);
	bpf_program__set_autoload(obj->progs.trace_super_drop_inode_exit, false);

	bpf_program__set_autoload(obj->progs.trace_super_evict_inode_entry, false);
	bpf_program__set_autoload(obj->progs.trace_super_evict_inode_exit, false);

	bpf_program__set_autoload(obj->progs.trace_super_show_devname_entry, false);
	bpf_program__set_autoload(obj->progs.trace_super_show_devname_exit, false);

	bpf_program__set_autoload(obj->progs.trace_super_show_options_entry, false);
	bpf_program__set_autoload(obj->progs.trace_super_show_options_exit, false);

	bpf_program__set_autoload(obj->progs.trace_super_umount_begin_entry, false);
	bpf_program__set_autoload(obj->progs.trace_super_umount_begin_exit, false);

	bpf_program__set_autoload(obj->progs.trace_super_freeze_entry, false);
	bpf_program__set_autoload(obj->progs.trace_super_freeze_exit, false);
}

static int adspace_fentry_set_attach_target(struct smbvfsslower_bpf *obj)
{
	int err = 0;
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_read_folio_entry, 0,
						     "cifs_read_folio");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_read_folio_exit, 0,
						     "cifs_read_folio");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_readahead_entry, 0,
						     "cifs_readahead");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_readahead_exit, 0,
						     "cifs_readahead");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_writepages_entry, 0,
						     "cifs_writepages");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_writepages_exit, 0,
						     "cifs_writepages");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_write_begin_entry, 0,
						     "cifs_write_begin");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_write_begin_exit, 0,
						     "cifs_write_begin");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_write_end_entry, 0,
						     "cifs_write_end");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_write_end_exit, 0,
						     "cifs_write_end");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_dirty_folio_entry, 0,
						     "netfs_dirty_folio");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_dirty_folio_exit, 0,
						     "netfs_dirty_folio");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_release_folio_entry,
						     0, "cifs_release_folio");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_release_folio_exit, 0,
						     "cifs_release_folio");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_direct_io_entry, 0,
						     "cifs_direct_io");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_direct_io_exit, 0,
						     "cifs_direct_io");

	err = err   ?:
		      bpf_program__set_attach_target(
			      obj->progs.trace_adspace_invalidate_folio_entry, 0,
			      "cifs_invalidate_folio");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_invalidate_folio_exit,
						     0, "cifs_invalidate_folio");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_launder_folio_entry,
						     0, "cifs_launder_folio");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_launder_folio_exit, 0,
						     "cifs_launder_folio");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_migrate_folio_entry,
						     0, "filemap_migrate_folio");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_migrate_folio_exit, 0,
						     "filemap_migrate_folio");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_swap_activate_entry,
						     0, "cifs_swap_activate");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_swap_activate_exit, 0,
						     "cifs_swap_activate");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_swap_deactivate_entry,
						     0, "cifs_swap_deactivate");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_swap_deactivate_exit,
						     0, "cifs_swap_deactivate");

	return err;
}

static void adspace_fentry_disable_target(struct smbvfsslower_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.trace_adspace_read_folio_entry, 0);
	bpf_program__set_autoload(obj->progs.trace_adspace_read_folio_exit, 0);

	bpf_program__set_autoload(obj->progs.trace_adspace_readahead_entry, 0);
	bpf_program__set_autoload(obj->progs.trace_adspace_readahead_exit, 0);

	bpf_program__set_autoload(obj->progs.trace_adspace_writepages_entry, 0);
	bpf_program__set_autoload(obj->progs.trace_adspace_writepages_exit, 0);

	bpf_program__set_autoload(obj->progs.trace_adspace_write_begin_entry, 0);
	bpf_program__set_autoload(obj->progs.trace_adspace_write_begin_exit, 0);

	bpf_program__set_autoload(obj->progs.trace_adspace_write_end_entry, 0);
	bpf_program__set_autoload(obj->progs.trace_adspace_write_end_exit, 0);

	bpf_program__set_autoload(obj->progs.trace_adspace_dirty_folio_entry, 0);
	bpf_program__set_autoload(obj->progs.trace_adspace_dirty_folio_exit, 0);

	bpf_program__set_autoload(obj->progs.trace_adspace_release_folio_entry, 0);
	bpf_program__set_autoload(obj->progs.trace_adspace_release_folio_exit, 0);

	bpf_program__set_autoload(obj->progs.trace_adspace_direct_io_entry, 0);
	bpf_program__set_autoload(obj->progs.trace_adspace_direct_io_exit, 0);

	bpf_program__set_autoload(obj->progs.trace_adspace_invalidate_folio_entry, 0);
	bpf_program__set_autoload(obj->progs.trace_adspace_invalidate_folio_exit, 0);

	bpf_program__set_autoload(obj->progs.trace_adspace_launder_folio_entry, 0);
	bpf_program__set_autoload(obj->progs.trace_adspace_launder_folio_exit, 0);

	bpf_program__set_autoload(obj->progs.trace_adspace_migrate_folio_entry, 0);
	bpf_program__set_autoload(obj->progs.trace_adspace_migrate_folio_exit, 0);

	bpf_program__set_autoload(obj->progs.trace_adspace_swap_activate_entry, 0);
	bpf_program__set_autoload(obj->progs.trace_adspace_swap_activate_exit, 0);

	bpf_program__set_autoload(obj->progs.trace_adspace_swap_deactivate_entry, 0);
	bpf_program__set_autoload(obj->progs.trace_adspace_swap_deactivate_exit, 0);
}

static void print_headers()
{
	if (csv) {
		printf("ENDTIME_us,TASK,PID,TYPE,FUNCTION,LATENCY_us\n");
		return;
	}

	printf("Tracing SMB VFS callbacks for: ");

	if (num_selected_callbacks > 0) {
		printf("specific callbacks [");
		for (int i = 0; i < num_selected_callbacks; i++) {
			printf("%s%s", selected_callbacks[i], 
			       i < num_selected_callbacks - 1 ? ", " : "");
		}
		printf("], ");
	} else {
		if (file_ops)
			printf("file operations, ");

		if (inode_ops)
			printf("inode operations, ");

		if (adspace_ops)
			printf("address space operations, ");

		if (super_ops)
			printf("superblock operations, ");
	}

	if (target_pid)
		printf("PID=%d, ", target_pid);

	printf("latency more than %llu ms... ", min_lat_ms);

	if (duration)
		printf(" for %ld secs.\n", duration);
	else
		printf("Hit Ctrl-C to end.\n");

	printf("%-15s %-20s %-7s %-10s %-25s %-7s\n", "ENDTIME", "TASK", "PID", "TYPE", "FUNCTION",
	       "LATENCY(ms)");
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;
	struct tm *tm;
	char ts[32];
	time_t t;
	struct timeval tv;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}

	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	if (csv) {
		//reverse map the command
		printf("%lld,%s,%ld,%s,%s,%lld\n,", e.when_release_us, e.task, e.pid, e.type,
		       e.function, e.delta_us);
		return;
	}

	gettimeofday(&tv, NULL);
	t = tv.tv_sec;
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	snprintf(ts + strlen(ts), sizeof(ts) - strlen(ts), ".%06ld", tv.tv_usec);

	printf("%-15s %-20s %-7ld %-10s %-25s %-7.3f\n", ts, e.task, e.pid, e.type, e.function,
	       (double)e.delta_us / 1000);
}

static struct timespec get_end_time_from_duration()
{
	struct timespec end_time, start_time;
	clock_gettime(CLOCK_REALTIME, &start_time);
	long long duration_ns = (long long)duration * NSEC_PER_SEC;
	end_time.tv_sec = start_time.tv_sec + duration_ns / NSEC_PER_SEC;
	end_time.tv_nsec = start_time.tv_nsec + duration_ns % NSEC_PER_SEC;

	if (end_time.tv_nsec >= NSEC_PER_SEC) {
		end_time.tv_sec += 1;
		end_time.tv_sec -= NSEC_PER_SEC;
	}
	return end_time;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

/* Helper to disable all programs when using individual callback selection */
static void disable_all_programs(struct smbvfsslower_bpf *obj)
{
	file_fentry_disable_target(obj);
	inode_fentry_disable_attach_target(obj);
	super_fentry_disable_target(obj);
	adspace_fentry_disable_target(obj);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct smbvfsslower_bpf *skel;
	struct timespec end_time, current_time;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Handle --list option */
	if (list_callbacks) {
		list_all_callbacks();
		return 0;
	}

	libbpf_set_print(libbpf_print_fn);

	skel = smbvfsslower_bpf__open_opts(&open_opts);
	if (!skel) {
		warn("failed to open BPF object\n");
		return 1;
	}

	skel->rodata->target_pid = target_pid;
	skel->rodata->min_lat_ns = min_lat_ms * 1000 * 1000;

	// Handle individual callback selection
	if (num_selected_callbacks > 0) {
		/* Disable all programs first */
		disable_all_programs(skel);

		/* Then enable only selected callbacks */
		for (int i = 0; i < num_selected_callbacks; i++) {
			err = attach_specific_callback(skel, selected_callbacks[i]);
			if (err) {
				warn("failed to attach callback '%s': %d\n", selected_callbacks[i], err);
				goto cleanup;
			}
			if (verbose)
				printf("Attached to callback: %s\n", selected_callbacks[i]);
		}
	}
	// Handle category-based selection (original behavior)
	else {
		// conditional attachment: disable rest of the probes
		if (!file_ops && !inode_ops && !adspace_ops && !super_ops) {
			warn("No operations selected. Try 'smbvfsslower --help'\n");
			goto cleanup;
		}

		if (file_ops) {
			err = file_fentry_set_attach_target(skel);
			if (err) {
				warn("failed to set (file) attach target: %d\n", err);
				goto cleanup;
			}
		} else {
			file_fentry_disable_target(skel);
		}

		if (inode_ops) {
			err = inode_fentry_set_attach_target(skel);
			if (err) {
				warn("failed to set (inode) attach target: %d\n", err);
				goto cleanup;
			}
		} else {
			inode_fentry_disable_attach_target(skel);
		}

		if (adspace_ops) {
			err = super_fentry_set_attach_target(skel);
			if (err) {
				warn("failed to set (super) attach target: %d\n", err);
				goto cleanup;
			}
		} else {
			adspace_fentry_disable_target(skel);
		}

		if (super_ops) {
			err = adspace_fentry_set_attach_target(skel);
			if (err) {
				warn("failed to set (address space) attach target: %d\n", err);
				goto cleanup;
			}
		} else {
			super_fentry_disable_target(skel);
		}
	}

	err = smbvfsslower_bpf__load(skel);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/*
	 * after load
	 * if fentry is supported, let libbpf do auto load
	 */
	err = smbvfsslower_bpf__attach(skel);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started\n");

	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES, handle_event,
			      handle_lost_events, NULL, NULL);

	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	print_headers();

	if (duration)
		end_time = get_end_time_from_duration();

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}

		if (duration) {
			clock_gettime(CLOCK_REALTIME, &current_time);
			double elapsed_seconds = difftime(current_time.tv_sec, end_time.tv_sec);
			if (elapsed_seconds > 0)
				goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	smbvfsslower_bpf__destroy(skel);

	/* Free allocated callback names */
	for (int i = 0; i < num_selected_callbacks; i++) {
		free(selected_callbacks[i]);
	}

	return err != 0;
}