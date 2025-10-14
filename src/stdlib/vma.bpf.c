#define __KERNEL__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

extern int bpf_iter_task_vma_new(struct bpf_iter_task_vma *it,
                                 struct task_struct *task, u64 addr) __ksym __weak;
extern struct vm_area_struct *bpf_iter_task_vma_next(struct bpf_iter_task_vma *it) __ksym __weak;
void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it) __ksym __weak;


unsigned long __bpf_task_map_file_min_addr(unsigned long ino)
{
  struct bpf_iter_task_vma vma_it;
  struct vm_area_struct *vma;
  struct task_struct *cur_task = bpf_get_current_task_btf();
  unsigned long off = 0xffffffffffffffffUL;
  _Bool found = false;

  if (!bpf_iter_task_vma_new)
    return 0;

  if (bpf_iter_task_vma_new(&vma_it, cur_task, 0)) {
    goto cleanup;
  }

  while ((vma = bpf_iter_task_vma_next(&vma_it))) {
    struct file *file = vma->vm_file;
    if (file) {
      struct inode *inode = file->f_inode;
      if (inode->i_ino == ino) {
        found = true;
        if (off > vma->vm_start) {
          off = vma->vm_start;
        }
      }
    }
  }

cleanup:
  bpf_iter_task_vma_destroy(&vma_it);
  return found ? off : 0;
}
