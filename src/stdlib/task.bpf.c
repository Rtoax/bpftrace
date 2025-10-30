#define __KERNEL__
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

extern struct task_struct *bpf_task_from_pid(s32 pid) __weak __ksym;
extern void bpf_task_release(struct task_struct *p) __weak __ksym;

void *__task_from_pid(s32 pid)
{
  // linux >= 6.1
  if (!bpf_task_from_pid)
    return NULL;

   return bpf_task_from_pid(pid);
}

void __task_release(void *task)
{
  // linux >= 6.1
  if (!bpf_task_release)
    return;

  bpf_task_release(task);
}
