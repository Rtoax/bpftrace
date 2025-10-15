#define __KERNEL__
#include <linux/types.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct bpf_iter_task_vma {
  __u64 __opaque[1];
  // Make sure this structure is larger than the kernel.
  __u64 reserved[4];
};

// In order to ensure that the custom BTF does not conflict with the kernel's
// native BTF as much as possible, we try to avoid using vmlinux.h directly.
// CO-RE is a good choice.
struct inode___o {
  unsigned long i_ino;
} __attribute__((preserve_access_index));

struct file___o {
  struct inode___o *f_inode;
} __attribute__((preserve_access_index));

struct task_struct___o {
} __attribute__((preserve_access_index));

struct vm_area_struct___o {
  unsigned long vm_start;
  struct file___o *vm_file;
} __attribute__((preserve_access_index));

extern int bpf_iter_task_vma_new(struct bpf_iter_task_vma *it,
                                 struct task_struct___o *task, __u64 addr) __ksym __weak;
extern struct vm_area_struct___o *bpf_iter_task_vma_next(struct bpf_iter_task_vma *it) __ksym __weak;
extern void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it) __ksym __weak;


unsigned long __bpf_task_map_file_min_addr(unsigned long ino)
{
  // linux >= 6.7
  if (!bpf_iter_task_vma_new)
    return 0;

  struct bpf_iter_task_vma vma_it;
  void *vmaptr;
  struct vm_area_struct___o *vma;
  struct task_struct___o *cur_task = (void *)bpf_get_current_task_btf();
  unsigned long off = 0xffffffffffffffffUL;
  _Bool found = 0;

  if (bpf_iter_task_vma_new(&vma_it, cur_task, 0)) {
    bpf_iter_task_vma_destroy(&vma_it);
    return 0;
  }

  while ((vmaptr = bpf_iter_task_vma_next(&vma_it))) {
    vma = (void *)vmaptr;
    struct file___o *file = (void *)BPF_CORE_READ(vma, vm_file);
    if (file) {
      struct inode___o *inode = (void *)BPF_CORE_READ(file, f_inode);
      if ((unsigned long)BPF_CORE_READ(inode, i_ino) == ino) {
        found = 1;
        unsigned long vm_start = (unsigned long)BPF_CORE_READ(vma, vm_start);
        if (off > vm_start) {
          off = vm_start;
        }
      }
    }
  }

  bpf_iter_task_vma_destroy(&vma_it);
  return found ? off : 0;
}
