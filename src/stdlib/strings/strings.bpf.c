#define __KERNEL__
#include <asm/errno.h>
#include <asm/posix_types.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>
#include "errors.h"
#include "syscall.h"

#if 0
struct map_str {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, err_str);
  __uint(max_entries, 128);
};

extern struct map_str map_strerrors SEC(".map");
#endif

extern int bpf_strnlen(const char *s__ign, size_t count) __ksym __weak;

long __bpf_strnlen(const char *ptr, size_t max_size)
{
  if (bpf_strnlen) {
    return bpf_strnlen(ptr, max_size);
  }
  long sz = 0;
  for (size_t i = 0; i < max_size; ++i) {
    if (ptr[i] == 0) {
      break;
    }
    ++sz;
  }
  return sz;
}

extern int bpf_strnstr(const char *s1__ign,
                       const char *s2__ign,
                       size_t len) __ksym __weak;

int __bpf_strnstr(const char *haystack,
                   const char *needle,
                   size_t haystack_size,
                   size_t needle_size)
{
  if (bpf_strnstr) {
    return bpf_strnstr(haystack, needle, haystack_size);
  }
  if (needle_size > haystack_size) {
    return -1;
  }
  for (size_t i = 0; i < haystack_size; i++) {
    size_t j;
    if (haystack[i] == 0) {
      break;
    }
    for (j = 0; j < needle_size; j++) {
      if (needle[j] == 0) {
        return (int)i;
      }
      size_t k = i + j;
      if (k > haystack_size) {
        break;
      }
      if (haystack[k] != needle[j]) {
        break;
      }
    }

    if (j == needle_size) {
      return (int)i;
    }
  }
  return -1;
}

int __strerror(int errno, err_str *out) {
  if (errno < 0) {
    errno = -errno;
  }
#if 0 // works fine
  __builtin_memcpy(out, &unknown_error, sizeof(*out));
#endif
#if 0
  err_str *str = bpf_map_lookup_elem(&map_strerrors, &errno);
  if (!str) {
    bpf_map_update_elem(&map_strerrors, &errno, &unknown_error, BPF_NOEXIST);
  }
  //str = bpf_map_lookup_elem(&map_strerrors, &errno);
  //__builtin_memcpy(out, str, sizeof(*out));
  __builtin_memcpy(out, &unknown_error, sizeof(*out));
#endif
#if 1 /* Looks like the BPF stack limit is exceeded. */
  if (errno >= 0 && errno <= EHWPOISON) {
    __builtin_memcpy(out, &errors[errno], sizeof(*out));
  } else {
    __builtin_memcpy(out, &unknown_error, sizeof(*out));
  }
#endif
  return 0;
}

int __syscall_name(int n, syscall_str *out) {
  if (n >= 0 && n < NR_SYSCALL_ALIGN_BITS) {
    // To resolve the verifier's complaint that the off range is too large,
    // resulting in "possible" access beyond the range of syscall_names[],
    // we use a constant value to constrain n to help the verifier.
    n &= NR_SYSCALL_ALIGN_BITS;

    // System call numbers are not sequential, so when syscall_names is empty,
    // we return "unknown system call".
    if (syscall_names[n][0] == '\0') {
      __builtin_memcpy(out, &unknown_syscall, sizeof(*out));
    } else {
      __builtin_memcpy(out, &syscall_names[n], sizeof(*out));
    }
  } else {
    __builtin_memcpy(out, &unknown_syscall, sizeof(*out));
  }
  return 0;
}
