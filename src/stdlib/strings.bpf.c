#define __KERNEL__
#include <asm/errno.h>
#include <asm/posix_types.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>
#include "errors.h"
#include "strings.h"
#include "syscall.h"

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

m_str* __strerror(int errno, m_arg *out) {
  m_str *result;
  if (errno < 0) {
    errno = -errno;
  }
  if (errno >= 0 && errno <= EHWPOISON) {
    result = &errors[errno];
  } else {
    result = &unknown_error;
  }
  __builtin_memcpy(&out->data, result, sizeof(*out));
  return &out->data;
}

m_str* __syscall_name(int n, m_arg *out) {
  m_str *result;
  char ch;

  if (n >= 0 && n < syscall_names_size) {
    result = &syscall_names[n];
  } else {
    result = &unknown_syscall;
  }

  // Syscall numbers are not spaced by 1.
  if (bpf_probe_read_kernel(&ch, sizeof(ch), (void*)*result) == 0) {
    if (ch == '\0') {
      result = &unknown_syscall;
    }
  } else {
    result = &unknown_syscall;
  }

  bpf_probe_read_kernel(&out->data, sizeof(out->data), result);
  return &out->data;
}
