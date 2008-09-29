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

#include "json.h"

#include "util.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>

#define MAX_ELEMENT 10000

typedef struct {
  uint32_t required_size;
  const char* data;
  const char* end;
} Parser;

static int align(int len) {
  return (len + 7)&~7;
}

static void* chunk_alloc(Parser* p, void* data, int size) {
  void* v = safe_malloc(size);
  memcpy(v, data, size);
  p->required_size += align(size);
  return v;
}

/* Should already be advanced to a token before calling this */
static int parse(Parser* p, JSON_Value* r);

static int parse_error(const char* format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fputc('\n', stderr);
  return 0;
}

static int advance_to_token(Parser* p) {
  const char* d = p->data;
  const char* e = p->end;

  while (d < e && isspace(*d)) {
    ++d;
  }
  if (d == e)
    return parse_error("Unexpected end of input scanning for token");
  p->data = d;

  return 1;
}

static int parse_string(Parser* p, JSON_Value* r) {
  int str_len = 0;
  CH_StaticBuf buf;
  
  init_static_buf(&buf);

  p->data++;
  while (p->data < p->end && *p->data != '"') {
    char ch = *p->data;
    if (ch == '\\') {
      if (p->end - p->data < 2)        
        return parse_error("Unexpected end of input reading string");
      
      p->data++;
      ch = *p->data;
      if (ch == 'u') {
        /* TODO convert the Unicode character to UTF8 */
        fatal_error(99, "Unicode characters not supported yet");
        continue;
      } else {
        switch (ch) {
        case 'b': ch = '\b'; break;
        case 'f': ch = '\f'; break;
        case 'n': ch = '\n'; break;
        case 'r': ch = '\r'; break;
        case 't': ch = '\t'; break;
        }
      }
    } else if (ch < 0x20) {
      return parse_error("Unexpected control character in string");
    }

    static_ensure_buffer_size(&buf, str_len + 1);
    buf.data[str_len] = ch;
    ++str_len;
    p->data++;
  }
  if (p->data == p->end)
    return parse_error("Unexpected end of input reading string");

  p->data++;

  /* null terminate the string */
  static_ensure_buffer_size(&buf, str_len + 1);
  buf.data[str_len] = 0;
  r->type = JSON_STRING;
  r->v.s = chunk_alloc(p, buf.data, str_len + 1);
  safe_free(buf.dynamic_data);
  return 1;
}

static int parse_array(Parser* p, JSON_Value* r) {
  int array_len = 0;
  CH_StaticBuf buf;
  init_static_buf(&buf);

  p->data++;
  if (!advance_to_token(p))
    return 0;
  if (*p->data != ']') {
    for (;;) {
      JSON_Value r;

      if (!parse(p, &r)) {
        safe_free(buf.dynamic_data);
        return 0;
      }
      static_ensure_buffer_size(&buf, (array_len+1)*sizeof(JSON_Value));
      ((JSON_Value*)buf.data)[array_len] = r;
      ++array_len;
      
      if (!advance_to_token(p)) {
        safe_free(buf.dynamic_data);
        return 0;
      }
      if (*p->data == ',') {
        p->data++;
        if (!advance_to_token(p)) {
          safe_free(buf.dynamic_data);
          return 0;
        }
        continue;
      }

      if (*p->data == ']') {
        p->data++;
        break;
      }
      
      return parse_error("Unexpected character '%c' parsing array", *p->data);
    }
  }

  static_ensure_buffer_size(&buf, (array_len+1)*sizeof(JSON_Value));
  ((JSON_Value*)buf.data)[array_len].type = JSON_INVALID;
  r->type = JSON_ARRAY;
  r->v.a = chunk_alloc(p, buf.data, (array_len+1)*sizeof(JSON_Value));
  safe_free(buf.dynamic_data);
  return 1;
}

static int parse_object(Parser* p, JSON_Value* r) {
  int array_len = 0;
  CH_StaticBuf buf;
  init_static_buf(&buf);

  p->data++;
  if (!advance_to_token(p))
    return 0;
  if (*p->data != '}') {
    for (;;) {
      JSON_Value f, r;

      if (!parse(p, &f))
        return 0;
      if (f.type != JSON_STRING)
        return parse_error("Field name not a string");

      if (!advance_to_token(p)) {
        safe_free(buf.dynamic_data);
        return 0;
      }
      if (*p->data != ':') {
        safe_free(buf.dynamic_data);
        return parse_error("Field name not followed by ':'");
      }
      p->data++;

      if (!advance_to_token(p) || !parse(p, &r)) {
        safe_free(buf.dynamic_data);
        return 0;
      }

      static_ensure_buffer_size(&buf, (array_len+2)*sizeof(JSON_Value));
      ((JSON_Value*)buf.data)[array_len] = f;
      ((JSON_Value*)buf.data)[array_len+1] = r;
      array_len += 2;
      
      if (!advance_to_token(p)) {
        safe_free(buf.dynamic_data);
        return 0;
      }
      if (*p->data == ',') {
        p->data++;
        if (!advance_to_token(p)) {
          safe_free(buf.dynamic_data);
          return 0;
        }
        continue;
      }

      if (*p->data == '}') {
        p->data++;
        break;
      }
      
      safe_free(buf.dynamic_data);
      return parse_error("Unexpected character '%c' parsing object", *p->data);
    }
  }

  static_ensure_buffer_size(&buf, (array_len+1)*sizeof(JSON_Value));
  ((JSON_Value*)buf.data)[array_len].type = JSON_INVALID;
  r->type = JSON_OBJECT;
  r->v.a = chunk_alloc(p, buf.data, (array_len+1)*sizeof(JSON_Value));
  safe_free(buf.dynamic_data);
  return 1;
}

static int parse_keyword(Parser* p, JSON_Value* r, const char* k,
                         JSON_Type t) {
  while (p->data < p->end && *k != 0 && *p->data == *k) {
    p->data++, k++;
  }
  if (*k != 0)
    return parse_error("Unexpected end of input reading keyword");
    
  r->type = t;

  return 1;
}

static int parse_number(Parser* p, JSON_Value* r) {
  int sign = 1;
  int num_digits = 0;
  int64_t v = 0;

  if (*p->data == '-') {
    sign = -1;
    p->data++;
  }

  for (;;) {
    if (p->data >= p->end || *p->data < '0' || *p->data > '9')
      break;
    v = 10*v + (*p->data - '0');
    p->data++;
    ++num_digits;
  }

  if (num_digits == 0)
    return parse_error("Unexpected end of input reading number");

  if (p->data < p->end &&
      (*p->data == '.' || *p->data == 'e' || *p->data == 'E')) {
    fatal_error(99, "Floating point not implemented yet");
  }

  r->type = JSON_INT;
  r->v.i = v;
  
  return 1;
}

static int parse(Parser* p, JSON_Value* r) {
  switch (*p->data) {
  case '"': return parse_string(p, r);
  case '[': return parse_array(p, r);
  case '{': return parse_object(p, r);
  case 'f': return parse_keyword(p, r, "false", JSON_FALSE);
  case 't': return parse_keyword(p, r, "true", JSON_TRUE);
  case 'n': return parse_keyword(p, r, "null", JSON_NULL);
  default: return parse_number(p, r);
  }
}

static JSON_Value* copy_contents_into(JSON_Value* v, JSON_Value* r) {
  switch (v->type) {
  case JSON_STRING: {
    char* ptr = (char*)r;
    int len = strlen(v->v.s) + 1;
    memcpy(ptr, v->v.s, len);
    safe_free((char*)v->v.s);
    v->v.s = ptr;
    ptr += align(len);
    return (JSON_Value*)ptr;
  }
  case JSON_ARRAY:
  case JSON_OBJECT: {
    int i;
    JSON_Value* t = r;
    for (i = 0; v->v.a[i].type != JSON_INVALID; ++i) {
      *r = v->v.a[i];
      r++;
    }
    *r = v->v.a[i];
    r++;
    safe_free(v->v.a);
    v->v.a = t;
    for (i = 0; v->v.a[i].type != JSON_INVALID; ++i) {
      r = copy_contents_into(&v->v.a[i], r);
    }
    return r;
  }
  default:
    return r;
  }
}

JSON_Value* JSON_parse(const char* data, int len) {
  Parser p;
  JSON_Value r;
  JSON_Value* result;

  p.required_size = sizeof(JSON_Value);
  p.data = data;
  p.end = data + len;

  if (!advance_to_token(&p))
    return NULL;
  if (!parse(&p, &r))
    return NULL;

  result = safe_malloc(p.required_size);
  *result = r;
  copy_contents_into(result, result + 1);
  return result;
}

/* returns NULL if no such field */
JSON_Value* JSON_get_field(JSON_Value* v, const char* name) {
  int i = 0;
  if (v->type != JSON_OBJECT)
    fatal_error(32, "JSON value not an object (%d)", v->type);

  while (v->v.o[i].type == JSON_STRING) {
    if (strcmp(v->v.o[i].v.s, name) == 0)
      return &v->v.o[i+1];
    i += 2;
  }

  return NULL;
}

int JSON_is_string(JSON_Value* v, const char* s) {
  if (v->type != JSON_STRING)
    return 0;
  return strcmp(v->v.s, s) == 0;
}

static void append_value(JSON_Builder* builder, JSON_Value* v) {
  builder->buf_count++;
  ensure_buffer_size(&builder->buf, sizeof(JSON_Value)*builder->buf_count);
  ((JSON_Value*)builder->buf.data)[builder->buf_count-1] = *v;
}

static void* append_data(JSON_Builder* builder, int size) {
  void* r;
  builder->block_buf_count++;
  ensure_buffer_size(&builder->block_buf, sizeof(void*)*builder->block_buf_count);
  r = safe_malloc(size);
  ((void**)builder->block_buf.data)[builder->block_buf_count - 1] = r;
  return r;
}

static void JSON_builder_init(JSON_Builder* builder) {
  init_buf(&builder->buf);
  builder->buf_count = 0;
  init_buf(&builder->block_buf);
  builder->block_buf_count = 0;
}

void JSON_builder_init_object(JSON_Builder* builder) {
  JSON_builder_init(builder);
  JSON_append_simple(builder, NULL, JSON_OBJECT);
}

void JSON_builder_init_array(JSON_Builder* builder) {
  JSON_builder_init(builder);
  JSON_append_simple(builder, NULL, JSON_ARRAY);
}

static int get_end_of(JSON_Builder* builder, int index) {
  JSON_Value* v = &((JSON_Value*)builder->buf.data)[index];
  switch (v->type) {
    case JSON_OBJECT:
    case JSON_ARRAY: {
      ++index;
      while (index < builder->buf_count &&
             ((JSON_Value*)builder->buf.data)[index].type != JSON_INVALID) {
        index = get_end_of(builder, index);
      }
      if (index >= builder->buf_count)
        return index;
      return index + 1;
    }
    default:
      return index + 1;
  }
}

void JSON_builder_init_copy_part(JSON_Builder* builder, JSON_Builder* source,
                                 int* index) {
  int i = *index;
  int end = get_end_of(source, i);

  JSON_builder_init(builder);
  while (i < end - 1) {
    append_value(builder, (JSON_Value*)source->buf.data + i);
    ++i;
  }
  *index = end;
}

void JSON_append_int(JSON_Builder* builder, const char* field, int64_t i) {
  JSON_Value v;
  v.type = JSON_INT;
  v.v.i = i;
  if (field) {
    JSON_append_string(builder, NULL, field);
  }
  append_value(builder, &v);
}

void JSON_append_double(JSON_Builder* builder, const char* field, double d) {
  JSON_Value v;
  v.type = JSON_DOUBLE;
  v.v.d = d;
  if (field) {
    JSON_append_string(builder, NULL, field);
  }
  append_value(builder, &v);
}

void JSON_append_string(JSON_Builder* builder, const char* field, const char* str) {
  JSON_Value v;
  v.type = JSON_STRING;
  if (str == NULL) {
    fatal_error(44, "NULL string");
  }
  v.v.s = str;
  if (field) {
    JSON_append_string(builder, NULL, field);
  }
  append_value(builder, &v);
}

void JSON_append_stringdup(JSON_Builder* builder, const char* field, const char* str) {
  int len = strlen(str) + 1;
  char* v = append_data(builder, len);
  memcpy(v, str, len);
  JSON_append_string(builder, field, v);
}

static char hex_char(int v) {
  return "0123456789abcdef"[v];
}

static void append_hex_string(JSON_Builder* builder, const char* field_name,
                              uint8_t* data, uintptr_t len, uint8_t swap) {
  char* buf = safe_malloc(len*2 + 1);
  intptr_t i;
  if (data) {
    for (i = 0; i < len; ++i) {
      uint8_t b = data[swap ? len - 1 - i : i];
      buf[i*2] = hex_char(b >> 4);
      buf[i*2 + 1] = hex_char(b & 0xF);
    }
  } else {
    memset(buf, 0, len*2);
  }
  buf[len*2] = 0;
  JSON_append_stringdup(builder, field_name, buf);
  safe_free(buf);
}

void JSON_append_hex_string(JSON_Builder* builder, const char* field_name,
                            uint8_t* data, uintptr_t len) {
  append_hex_string(builder, field_name, data, len, 0);
}

void JSON_append_hex_string_byteswapped(JSON_Builder* builder, const char* field_name,
                                        uint8_t* data, uintptr_t len) {
  append_hex_string(builder, field_name, data, len, 1);
}

void JSON_append_stringf(JSON_Builder* builder, const char* field,
                         const char* format, ...) {
  va_list args;
  char buf[10240];
  
  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);
  buf[sizeof(buf) - 1] = 0;
  JSON_append_stringdup(builder, field, buf);
}

void JSON_append_boolean(JSON_Builder* builder, const char* field, int b) {
  JSON_append_simple(builder, field, b ? JSON_TRUE : JSON_FALSE);
}

void JSON_append_simple(JSON_Builder* builder, const char* field, JSON_Type t) {
  JSON_Value v;
  v.type = t;
  if (field) {
    JSON_append_string(builder, NULL, field);
  }
  append_value(builder, &v);
}

void JSON_open_object(JSON_Builder* builder, const char* field) {
  JSON_append_simple(builder, field, JSON_OBJECT);
}

void JSON_close_object(JSON_Builder* builder) {
  JSON_append_simple(builder, NULL, JSON_INVALID);
}

void JSON_open_array(JSON_Builder* builder, const char* field) {
  JSON_append_simple(builder, field, JSON_ARRAY);
}

void JSON_close_array(JSON_Builder* builder) {
  JSON_append_simple(builder, NULL, JSON_INVALID);
}

static int builder_print(JSON_Builder* builder, FILE* output, int i) {
  JSON_Value* v = &((JSON_Value*)builder->buf.data)[i];
  int j = i;
  switch (v->type) {
  case JSON_OBJECT:
    ++i;
    fputc('{', output);
    for (;;) {
      if (i >= builder->buf_count) {
        fputc('}', output);
        return i;
      }
      v = &((JSON_Value*)builder->buf.data)[i];
      if (v->type == JSON_INVALID) {
        fputc('}', output);
        return i + 1;
      }
      if (v->type != JSON_STRING)
        fatal_error(81, "Field expected");
      if (i > j + 1) {
        fputc(',', output);
      }
      if (i + 1 >= builder->buf_count)
        fatal_error(81, "Incomplete object");
      JSON_write(output, v);
      fputc(':', output);
      i = builder_print(builder, output, i + 1);
    }
    break;
  case JSON_ARRAY:
    ++i;
    fputc('[', output);
    for (;;) {
      if (i >= builder->buf_count) {
        fputc(']', output);
        return i;
      }
      v = &((JSON_Value*)builder->buf.data)[i];
      if (v->type == JSON_INVALID) {
        fputc(']', output);
        return i + 1;
      }
      if (i > j + 1) {
        fputc(',', output);
      }
      i = builder_print(builder, output, i);
    }
    break;
  default:
    JSON_write(output, v);
    return i + 1;
  }
}

void JSON_builder_done_write(JSON_Builder* builder, FILE* output) {
  JSON_builder_write(builder, output);
  JSON_builder_done(builder);
}

void JSON_builder_write(JSON_Builder* builder, FILE* output) {
  if (output) {
    if (builder_print(builder, output, 0) != builder->buf_count)
      fatal_error(81, "More than one value in the builder");
  }
}

void JSON_builder_done(JSON_Builder* builder) {
  int i;
  
  safe_free(builder->buf.data);
  for (i = 0; i < builder->block_buf_count; ++i) {
    safe_free(((void**)builder->block_buf.data)[i]);
  }
  safe_free(builder->block_buf.data);
}

void JSON_write(FILE* output, JSON_Value* v) {
  int i;
  char ch;
  switch (v->type) {
  case JSON_STRING:
    fputc('"', output);
    for (i = 0; (ch = v->v.s[i]) != 0; ++i) {
      switch (ch) {
      case '\n': fputs("\\n", output); break;
      case '\b': fputs("\\b", output); break;
      case '\f': fputs("\\f", output); break;
      case '\r': fputs("\\r", output); break;
      case '\t': fputs("\\t", output); break;
      default:
        if (ch < 0x20) {
          fprintf(output, "\\u%4x", ch);
        } else if ((unsigned char)ch >= 0x80) {
          fatal_error(80, "Unicode not supported yet");
        } else {
          fputc(ch, output);
        }
      }
    }
    fputc('"', output);
    break;
  case JSON_INT:
    fprintf(output, "%lld", (long long)v->v.i);
    break;
  case JSON_DOUBLE:
    fprintf(output, "%.99g", v->v.d);
    break;
  case JSON_ARRAY:
    fputc('[', output);
    for (i = 0; v->v.a[i].type != JSON_INVALID; ++i) {
      if (i > 0) {
        fputc(',', output);
      }
      JSON_write(output, &v->v.a[i]);
    }
    fputc(']', output);
    break;
  case JSON_OBJECT:
    fputc('{', output);
    for (i = 0; v->v.a[i].type != JSON_INVALID; i += 2) {
      if (i > 0) {
        fputs(", ", output);
      }
      JSON_write(output, &v->v.a[i]);
      fputc(':', output);
      JSON_write(output, &v->v.a[i+1]);
    }
    fputc('}', output);
    break;
  case JSON_NULL: fputs("null", output); return;
  case JSON_FALSE: fputs("false", output); return;
  case JSON_TRUE: fputs("true", output); return;
  default:
    fatal_error(77, "Unknown type");
  }
}
