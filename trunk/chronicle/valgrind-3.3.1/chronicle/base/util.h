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

#ifndef UTIL_H__
#define UTIL_H__

/*
 * Some utility functions for strings, memory allocation, etc.
 */

#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>

/**
 * A variable-size data buffer that can grow efficiently.
 */
typedef struct {
  uint8_t*  data;
  uintptr_t size;
} CH_GrowBuf;

/**
 * A variable-size data buffer that can grow efficiently and has 128 bytes
 * statically allocated within it. Nice and efficient for buffers that
 * are usually small.
 */
typedef struct {
  uint8_t*  data;
  uintptr_t size;

  uint8_t*  dynamic_data;
  uint8_t   static_area[128];
} CH_StaticBuf;

/**
 * A mutable UTF8 string object.
 */
typedef struct {
  CH_StaticBuf buf;
  uintptr_t    len;
} CH_StringBuf;

/**
 * Call this before calling any other functions defined here.
 */
void init_utils();

/**
 * Macro to init a CH_GrowBuf.
 */
#define init_buf(buf) do { (buf)->data = NULL; (buf)->size = 0; } while (0)
/**
 * Macro to init a CH_StaticBuf.
 */
#define init_static_buf(buf) do { (buf)->dynamic_data = NULL; \
    (buf)->data = (buf)->static_area; (buf)->size = sizeof((buf)->static_area); } while (0)

/*
 * Functions to manipulate CH_StringBufs. The first call must be stringbuf_init.
 * One of stringbuf_finish or stringbuf_destroy must be called last.
 */
/** Initialize a stringbuf before first use. */
void stringbuf_init(CH_StringBuf* buf);
/** Set a stringbuf to a given null-terminated string. */
void stringbuf_set(CH_StringBuf* buf, const char* str);
/** Append a null-terminated string to a stringbuf. */
void stringbuf_append(CH_StringBuf* buf, const char* str);
/**
 * Get the characters of a stringbuf (null terminated). Only valid
 * until the next operation on the stringbuf.
 */
const char* stringbuf_get(CH_StringBuf* buf);
/** Get the length of a stringbuf. */
#define stringbuf_len(buf) ((buf)->len)
/**
 * Destroy the stringbuf but return a malloc'ed null-terminated string
 * with its characters.
 */
char* stringbuf_finish(CH_StringBuf* buf);
/** Destroy the stringbuf. */
void stringbuf_destroy(CH_StringBuf* buf);

/**
 * Given a stringbuf that contains a file name (Unix conventions), canonicalize
 * it by removing patterns such as 'foo/..' and '/.'.
 */
void canonicalize_pathname(CH_StringBuf* buf);

/*
 * malloc/free wrappers that provide run-time logging and also terminate
 * the program instantly whenever out-of-memory is detected, so no error
 * handling is needed.
 */
void* safe_malloc_internal(uintptr_t size, char* file, int line);
/** Like malloc(), but never returns NULL. */
#define safe_malloc(size) \
  safe_malloc_internal((size), __FILE__, __LINE__)
/** Like realloc(), but never returns NULL. */
void* safe_realloc(void* p, uintptr_t size);
void safe_free(void* p);
/** Like strdup(), but never returns NULL. */
char* safe_strdup(const char* s);

/*
 * Error reporting utilities.
 */
/** Print the error and then exit with the given status code. */
void vfatal_error(int code, const char* format, va_list args);
void fatal_error(int code, const char* format, ...);
/**
 * Print the error and then exit with the given status code, along with
 * a text representation of errno.
 */
void fatal_perror(int code, const char* format, ...);
/** Print the warning but do not exit. */
void vwarning(int code, const char* format, va_list args);
void warning(int code, const char* format, ...);

/*
 * Buffer utilities
 */

void ensure_buffer_size_grow(CH_GrowBuf* buf, uintptr_t required_size);
void static_ensure_buffer_size_grow(CH_StaticBuf* buf, uintptr_t required_size);

/** Ensure that 'buf' has size >= required_size. */
#define ensure_buffer_size(buf, required_size) \
  do { if ((buf)->size < (required_size))		\
      ensure_buffer_size_grow((buf), (required_size)); } while (0)

/** Ensure that 'buf' has size >= required_size. */
#define static_ensure_buffer_size(buf, required_size) \
  do { if ((buf)->size < (required_size))			\
      static_ensure_buffer_size_grow((buf), (required_size)); } while (0)

/** Map page numbers to hash values. */
uint32_t hash_page_num(uintptr_t page_num, uint32_t size);

#endif
