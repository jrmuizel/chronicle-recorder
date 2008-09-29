/*
    Copyright (c) 2006 Novell and contributors:
        robert@ocallahan.org
    
    Permission is hereby granted, free of charge, to any person
    obtaining a copy of this software and associated documentation
    files (the "Software"), to deal in the Software without
    restriction, including without limitation the rights to use,
    copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following
    conditions:
    
    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
    OTHER DEALINGS IN THE SOFTWARE.
*/

#include "util.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

static int log_fd;

void init_utils() {
  if (0) {
    log_fd = open("memlog", O_WRONLY | O_CREAT | O_TRUNC);
  }
}

void* safe_malloc_internal(uintptr_t size, char* file, int line) {
  void* r = malloc(size);
  if (!r)
    fatal_error(10, "Out of memory allocating %d bytes\n", size);

  if (log_fd) {
    char buf[1024];
    sprintf(buf, "Allocated %lld bytes at %s:%d = %p\n",
	    (unsigned long long)size, file, line, r);
    write(log_fd, buf, strlen(buf));
  }
  return r;
}

void* safe_realloc(void* p, uintptr_t size) {
  void* r = realloc(p, size);
  if (!r && size)
    fatal_error(10, "Out of memory reallocating %d bytes\n", size);

  if (log_fd) {
    char buf[1024];
    sprintf(buf, "Realloced %p to %lld\n", r, (unsigned long long)size);
    write(log_fd, buf, strlen(buf));
  }
  return r;
}

void safe_free(void* p) {
  free(p);
  if (log_fd) {
    char buf[1024];
    sprintf(buf, "Freed %p\n", p);
    write(log_fd, buf, strlen(buf));
  }
}

char* safe_strdup(const char* s) {
  int len = strlen(s) + 1;
  char* v = safe_malloc(len);
  memcpy(v, s, len);
  return v;
}

void fatal_error(int code, const char* format, ...) {
  va_list args;

  va_start(args, format);
  vfatal_error(code, format, args);
  va_end(args);
}

void vfatal_error(int code, const char* format, va_list args) {
  vfprintf(stderr, format, args);
  fputc('\n', stderr);
  exit(code);
}

void warning(int code, const char* format, ...) {
  va_list args;

  va_start(args, format);
  vwarning(code, format, args);
  va_end(args);
}

void vwarning(int code, const char* format, va_list args) {
  vfprintf(stderr, format, args);
  fputc('\n', stderr);
}

void fatal_perror(int code, const char* format, ...) {
  va_list args;
  int err = errno;
  char buf[1024];

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);

  strerror_r(err, buf, sizeof(buf));
  fprintf(stderr, " (%s)\n", buf);
  exit(code);
}

void ensure_buffer_size_grow(CH_GrowBuf* buf, uintptr_t required_size) {
  uintptr_t new_size = buf->size*2;
  if (new_size < required_size) {
    new_size = required_size;
  }
  buf->data = safe_realloc(buf->data, new_size);

  buf->size = new_size;
}

void static_ensure_buffer_size_grow(CH_StaticBuf* buf, uintptr_t required_size) {
  uintptr_t new_size = buf->size*2;
  if (new_size < required_size) {
    new_size = required_size;
  }
  if (buf->data == buf->static_area) {
    buf->data = safe_malloc(new_size);
    memcpy(buf->data, buf->static_area, sizeof(buf->static_area));
  } else {
    buf->data = safe_realloc(buf->data, new_size);
  }
  buf->dynamic_data = buf->data;
  buf->size = new_size;
}

/* XXX should use Jenkins hash here */
uint32_t hash_page_num(uintptr_t page_num, uint32_t size) {
#if __WORDSIZE == 64
  uint64_t v1 = (uint32_t)(page_num >> 32)*31901901;
  uint64_t m1 = v1 ^ (v1 >> 8) ^ (v1 >> 16) ^ (v1 >> 24) ^ (v1 >> 32)
    ^ (v1 >> 40);
#else
  uint64_t m1 = 0;
#endif
  uint64_t v2 = ((uint32_t)page_num)*39019017;
  uint64_t m2 = v2 ^ (v2 >> 8) ^ (v2 >> 16) ^ (v2 >> 24) ^ (v2 >> 32)
    ^ (v2 >> 40);
  uint32_t mix = (uint32_t)m1 ^ (uint32_t)m2;
  return mix & (size - 1);
}

void stringbuf_init(CH_StringBuf* buf) {
  init_static_buf(&buf->buf);
  buf->len = 0;
}

void stringbuf_set(CH_StringBuf* buf, const char* str) {
  int len = strlen(str);
  static_ensure_buffer_size(&buf->buf, len);
  memcpy(buf->buf.data, str, len);
  buf->len = len;
}

void stringbuf_append(CH_StringBuf* buf, const char* str) {
  int len = strlen(str);
  static_ensure_buffer_size(&buf->buf, buf->len + len);
  memcpy(buf->buf.data + buf->len, str, len);
  buf->len += len;
}

static char* stringbuf_get_internal(CH_StringBuf* buf) {
  static_ensure_buffer_size(&buf->buf, buf->len + 1);
  buf->buf.data[buf->len] = 0;
  return (char*)buf->buf.data;
}

const char* stringbuf_get(CH_StringBuf* buf) {
  return stringbuf_get_internal(buf);
}

char* stringbuf_finish(CH_StringBuf* buf) {
  char* r = stringbuf_get_internal(buf);
  if (r == (char*)buf->buf.dynamic_data)
    return r;
  return safe_strdup(r);
}

void stringbuf_destroy(CH_StringBuf* buf) {
  safe_free(buf->buf.dynamic_data);
}

void canonicalize_pathname(CH_StringBuf* buf) {
  int i;
  for (i = 0; i < buf->len; ++i) {
    uint8_t* p = buf->buf.data + i;
    if (p[0] != '/' || p[1] != '.')
      continue;
    if (p[2] == '/' || p[2] == 0) {
      memmove(p, p + 2, buf->len - (i + 2));
      buf->len -= 2;
      --i;
      continue;
    }
    if (p[2] == '.' && (p[3] == '/' || p[3] == 0)) {
      int j = i - 1;
      while (j >= 0) {
        if (buf->buf.data[j] == '/')
          break;
        --j;
      }
      if (j >= 0) {
        memmove(buf->buf.data + j, p + 3, buf->len - (i + 3));
        buf->len -= i + 3 - j;
        i = j - 1;
        continue;
      }
    }
  }
}
