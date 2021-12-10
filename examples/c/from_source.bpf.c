#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u32 u32;

/* #define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \ */
/* BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, __u32, _value_type, _max_entries) */


char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define EPERM 1
#define MAX_STRING_SIZE 4096
#define MAX_BUFFER_SIZE 32768
#define MAX_BUFFERS 1
#define PATH_BUFFER 0

#undef container_of
#define container_of(ptr, type, member)                    \
	({                                                     \
		const typeof(((type *)0)->member) *__mptr = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); \
	})

typedef struct buffers {
    u8 buf[MAX_BUFFER_SIZE];
} bufs_t;

/* BPF_PERCPU_ARRAY(bufs, bufs_t, MAX_BUFFERS); */
/* BPF_PERCPU_ARRAY(bufs_off, __u32, MAX_BUFFERS);           // Holds offsets to bufs respectively */

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, bufs_t);
  __uint(max_entries, MAX_BUFFERS);
} bufs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, MAX_BUFFERS);
} bufs_off SEC(".maps");

char value[32];
unsigned int pid_namespace;
char source_comm[32];



static __always_inline bufs_t* get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off)
{
    bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline u32* get_buf_off(int buf_idx)
{
    return bpf_map_lookup_elem(&bufs_off, &buf_idx);
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
	return container_of(mnt, struct mount, mnt);
}

static __always_inline bool prepend_path(struct path *path, bufs_t *string_p) {
  char slash = '/';
  char null = '\0';
  int offset = MAX_STRING_SIZE;

  if (path == NULL || string_p == NULL) {
    return false;
  }

  struct dentry *dentry = path->dentry;
  struct vfsmount *vfsmnt = path->mnt;

  struct mount *mnt = real_mount(vfsmnt);

  struct dentry *parent;
  struct dentry *mnt_root;
  struct mount *m;
  struct qstr d_name;

#pragma unroll
  for (int i = 0; i < 30; i++) {
    parent = BPF_CORE_READ(dentry, d_parent);
    mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

    if (dentry == mnt_root) {
      m = BPF_CORE_READ(mnt, mnt_parent);
      if (mnt != m) {
        dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        mnt = m;
        continue;
      }
      break;
    }

    if (dentry == parent) {
      break;
    }

    // get d_name
    d_name = BPF_CORE_READ(dentry, d_name);

    offset -= (d_name.len + 1);
    if (offset < 0)
      break;

    int sz = bpf_probe_read_str(
        &(string_p->buf[(offset) & (MAX_STRING_SIZE - 1)]),
        (d_name.len + 1) & (MAX_STRING_SIZE - 1), d_name.name);
    if (sz > 1) {
      bpf_probe_read(
          &(string_p->buf[(offset + d_name.len) & (MAX_STRING_SIZE - 1)]), 1,
          &slash);
    } else {
      offset += (d_name.len + 1);
    }

    dentry = parent;
  }

  if (offset == MAX_STRING_SIZE) {
    return false;
  }

  bpf_probe_read(&(string_p->buf[MAX_STRING_SIZE - 1]), 1, &null);
  offset--;

  bpf_probe_read(&(string_p->buf[offset & (MAX_STRING_SIZE - 1)]), 1, &slash);
  set_buf_off(PATH_BUFFER, offset);
  return true;
}

static bool is_equal(const char *a, const char *b) {
#pragma unroll
  for (int i = 0; i < 32; i++) {
    if (a[i] == '\0' || b[i] == '\0')
      break;

    if (a[i] != b[i])
      return false;
  }
  return true;
}

static bool in_pid_ns(unsigned int pid_namespace, struct task_struct *t) {
  struct ns_common pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns);
  if (pid_namespace != pid_ns.inum) {
    bpf_printk("false");
    return false;
  }
  bpf_printk("true");
  return true;}

static struct file* get_task_file(struct task_struct *t){
    return BPF_CORE_READ(t, mm, exe_file);
}

static bool compare_path_in_buf(char source[]) {
  u32* offset = get_buf_off(PATH_BUFFER);
  if (offset == NULL)
    return false;

  bufs_t* string_p = get_buf(PATH_BUFFER);
  if (string_p == NULL)
    return false;

  bpf_printk("from the buffer : %s", &string_p->buf[*offset & (MAX_STRING_SIZE - 1)]);

  #pragma unroll
  for (int i = 0; i < 32; i++) {
    char buf_val;
    bpf_probe_read(&buf_val, sizeof(char), &string_p->buf[( *offset + i ) & (MAX_STRING_SIZE - 1)]);
    if (buf_val == '\0' || source[i] == '\0')
      break;

    if (buf_val != source[i])
      return false;
  }
  return true;
}


SEC("lsm/bprm_check_security")
int BPF_PROG(executable_block, struct linux_binprm *bprm, int ret) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  if (!in_pid_ns(pid_namespace, t))
    return ret;
  bpf_printk("in the container");
  if (ret != 0)
    return ret;
  char filename[32];

  bpf_probe_read_str(&filename, 32, bprm->filename);
  bool comp = is_equal(filename, value);

  struct task_struct *parent_task = BPF_CORE_READ(t, parent);

  struct file *file_p = get_task_file(parent_task);
  bufs_t* string_buf = get_buf(PATH_BUFFER);
  struct path f_path = BPF_CORE_READ(file_p, f_path);
  prepend_path(&f_path, string_buf);

  u32 *offset = get_buf_off(PATH_BUFFER);

  char source[] = "/usr/bin/bash";
  bool buf_comp = compare_path_in_buf(source);

  if (comp && buf_comp)
    return -EPERM;

  return ret;
}
