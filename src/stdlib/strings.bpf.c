#define __KERNEL__
#include <asm/errno.h>
#include <asm/posix_types.h>
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>

extern int bpf_strnlen(const char *s__ign, size_t count) __ksym __weak;

long __bpf_strnlen(const char *ptr, size_t max_size)
{
  if (bpf_strnlen) {
    return bpf_strnlen(ptr, max_size);
  }
  return -ENOSYS; // Not available, must fall back.
}

extern int bpf_strnstr(const char *s1__ign,
                       const char *s2__ign,
                       size_t len) __ksym __weak;

long __bpf_strnstr(const char *haystack,
                   const char *needle,
                   size_t max_size,
                   long *out)
{
  if (bpf_strnstr) {
    *out = bpf_strnstr(haystack, needle, max_size);
    return 0; // Successfully searched.
  }
  return -ENOSYS;
}

//long bpf_snprintf(char *str, __u32 str_size, const char *fmt, __u64 *data, __u32 data_len);
//extern int bpf_snprintf(char *str, unsigned int str_size, char *fmt, const void *args, unsigned int date_len);

long __bpf_str_append(char *dst, size_t dst_sz, const char *src)
{
#if 0
  if (!dst || !src)
    return -1;
  while (*(dst++));
  int i;
  for (i = 0; src[i] && i < 256; i++) {
    dst[i] = src[i];
  }
  dst[i] = '\0';
#elif 0
  int i, j;
  for (i = 0; dst[i] != '\0'; i++);
  for (j = 0; src[j] != '\0'; j++) {
    if (i >= dst_sz - 1) {
      break;
    }
    dst[i] = src[j];
    i++;
  }
  if (i < dst_sz) {
    dst[i] = '\0';
  } else {
    dst[dst_sz - 1] = '\0';
  }
#elif 0
  bpf_snprintf(dst, dst_sz, "%s%s", dst, src);
#endif
  return 0;
}
