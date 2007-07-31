/*
   This file is part of Chronicle, a tool for recording the complete
   execution behaviour of a program.

   Copyright (C) 2002-2005 Novell and contributors:
      robert@ocallahan.org

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#include "query.h"
#include "util.h"
#include "json.h"
#include "thread_util.h"
#include "debug.h"
#include "memory_map.h"
#include "effect_map_read.h"
#include "reg_reconstruct.h"

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#define MAX_QUERIES 32

static const char* db_file;
static int do_log;
static FILE* log_file;

static uintptr_t reg_log_entry_count;
static CH_DBRegLogEntry* reg_log_entries;
static CH_DBFileReader db;

static QueryThread* active_queries[MAX_QUERIES];
static pthread_mutex_t active_queries_mutex;
static pthread_cond_t active_queries_condition;

static pthread_mutex_t stdout_lock;
static pthread_mutex_t log_lock;

CH_DBFileReader* get_db() {
  return &db;
}

void debugger_output(JSON_Builder* builder) {
  if (log_file) {
    pthread_mutex_lock(&log_lock);
    fputc('>', log_file);
    JSON_builder_write(builder, log_file);
    fputc('\n', log_file);
    fflush(log_file);
    pthread_mutex_unlock(&log_lock);
  }
  
  pthread_mutex_lock(&stdout_lock);
  JSON_builder_done_write(builder, stdout);
  fputc('\n', stdout);
  fflush(stdout);
  pthread_mutex_unlock(&stdout_lock);
}

static void remove_query(QueryThread* q) {
  pthread_mutex_lock(&active_queries_mutex);
  if (active_queries[q->index] == q) {
    active_queries[q->index] = NULL;
  }
  pthread_mutex_unlock(&active_queries_mutex);
}

static void debugger_message(const char* severity, QueryThread* q, const char* code,
                             const char* en_format, va_list args) {
  JSON_Builder builder;
  char text[10240];
  int err = errno;

  errno = 0;
  JSON_builder_init_object(&builder);
  if (q) {
    JSON_append_int(&builder, "id", q->id);
  }
  JSON_append_string(&builder, "message", code);
  JSON_append_string(&builder, "severity", severity);
  vsnprintf(text, sizeof(text), en_format, args);
  text[sizeof(text) - 1] = 0;
  JSON_append_string(&builder, "text", text);

  if (err) {
    char buf[1024];

    JSON_append_int(&builder, "errno", err);
    strerror_r(err, buf, sizeof(buf));
    JSON_append_string(&builder, "errnotext", buf);
  }

  debugger_output(&builder);
}

void debugger_info(QueryThread* q, const char* code, const char* en_format, ...) {
  va_list args;

  va_start(args, en_format);
  debugger_info_v(q, code, en_format, args);
  va_end(args);
}

void debugger_info_v(QueryThread* q, const char* code, const char* en_format, va_list args) {
  debugger_message("info", q, code, en_format, args);
}

void debugger_warning(QueryThread* q, const char* code, const char* en_format, ...) {
  va_list args;

  va_start(args, en_format);
  debugger_warning_v(q, code, en_format, args);
  va_end(args);
}

void debugger_warning_v(QueryThread* q, const char* code, const char* en_format, va_list args) {
  debugger_message("warning", q, code, en_format, args);
}

void debugger_error(QueryThread* q, const char* code, const char* en_format, ...) {
  va_list args;

  va_start(args, en_format);
  debugger_error_v(q, code, en_format, args);
  va_end(args);
}

void debugger_error_v(QueryThread* q, const char* code, const char* en_format, va_list args) {
  JSON_Builder builder;
  int pre_terminated;

  if (!q) {
    debugger_message("error", q, code, en_format, args);
    return;
  }
  
  JSON_builder_init_object(&builder);
  JSON_append_int(&builder, "id", q->id);
  JSON_append_string(&builder, "terminated", "error");

  pthread_mutex_lock(&q->mutex);
  pre_terminated = q->sent_termination;
  if (!pre_terminated) {
    debugger_message("error", q, code, en_format, args);
    
    q->sent_termination = 1;
    q->cancelled = 1;
    debugger_output(&builder);
  } else {
    JSON_builder_done_write(&builder, NULL);
  }
  pthread_mutex_unlock(&q->mutex);
  
  remove_query(q);
}

void debugger_fatal_error(QueryThread* q, const char* code, const char* en_format, ...) {
  va_list args;

  va_start(args, en_format);
  debugger_fatal_error_v(q, code, en_format, args);
  va_end(args);
}

void debugger_fatal_error_v(QueryThread* q, const char* code, const char* en_format, va_list args) {
  debugger_message("fatal_error", q, code, en_format, args);
  exit(71);
}

static const char* JSON_type_as_string(JSON_Type t) {
  switch (t) {
    case JSON_ARRAY: return "array";
    case JSON_OBJECT: return "object";
    case JSON_INT: return "integer";
    case JSON_STRING: return "string";
    case JSON_NULL: return "null";
    case JSON_TRUE: return "true";
    case JSON_FALSE: return "false";
    default:
      return "?";
  }
}

static JSON_Value* check_field_of_type_internal(QueryThread* q, JSON_Value* v,
                                                const char* v_name,
                                                const char* field_name, JSON_Type t,
                                                int is_required) {
  JSON_Value* r = JSON_get_field(v, field_name);

  if (r == NULL) {
    if (is_required) {
      debugger_error(q, "missing.field.in.command", "No %s '%s' field in %s",
                     JSON_type_as_string(t), field_name, v_name);
    }
    return NULL;
  }

  if (r->type != t && is_required) {
    debugger_warning(q, "bad.type.in.command",
        "Field '%s' in %s requires type %s (got %s)", field_name, v_name,
        JSON_type_as_string(t), JSON_type_as_string(r->type));
    return NULL;
  }
  return r;
}

static JSON_Value* check_optional_field_of_type(QueryThread* q, JSON_Value* v,
                                                const char* v_name,
                                                const char* field_name, JSON_Type t) {
  return check_field_of_type_internal(q, v, v_name, field_name, t, 0);
}

static JSON_Value* check_field_of_type(QueryThread* q, JSON_Value* v,
                                       const char* v_name,
                                       const char* field_name, JSON_Type t) {
  return check_field_of_type_internal(q, v, v_name, field_name, t, 1);
}

/** The builder can contain either an object or an array of objects. If it's
    an array, each contained object will be output as a distinct query result. */
int complete_work(QueryThread* q, int amount, JSON_Builder* builder) {
  int died, pre_terminated, last_work;
  JSON_Builder tmp_builder;
  
  if (builder == NULL) {
    builder = &tmp_builder;
    JSON_builder_init_object(builder);
  } else {
    JSON_Value* v = &((JSON_Value*)builder->buf.data)[0];
    if (v->type == JSON_ARRAY) {
      int i = 1;
      int done = 0;
      while (i < builder->buf_count) {
        JSON_builder_init_copy_part(&tmp_builder, builder, &i);
        if (i < builder->buf_count) {
          if (!complete_work(q, 0, &tmp_builder)) {
            done = 1;
          }
        } else {
          if (!complete_work(q, amount, &tmp_builder)) {
            done = 1;
          }
          amount = 0;
        }
      }
      JSON_builder_done(builder);
      if (amount) {
        if (!complete_work(q, amount, NULL)) {
          done = 1;
        }
      }
      return !done;
    }
  }
  JSON_append_int(builder, "id", q->id);

  pthread_mutex_lock(&q->mutex);
  q->progress += amount;
  pre_terminated = q->sent_termination;
  last_work = q->progress == q->progress_max;
  died = !pre_terminated && (last_work || q->cancelled);
  if (died) {
    q->sent_termination = 1;
    JSON_append_string(builder, "terminated", last_work ? "normal" : "cancel");
  }
  if (!pre_terminated) {
    JSON_append_int(builder, "progress", q->progress);
    JSON_append_int(builder, "progressMax", q->progress_max);
    debugger_output(builder);
  } else {
    JSON_builder_done_write(builder, NULL);
  }
  pthread_mutex_unlock(&q->mutex);
  
  if (died) {
    remove_query(q);
  }

  if (last_work) {
    free(q);
  }
  
  return !died;
}

static void parse_options(int argc, char** argv) {
  argv++, argc--;
  db_file = getenv("CHRONICLE_DB");

  while (argc > 0) {
    if (strcmp(argv[0], "--db") == 0 && argc > 1) {
      db_file = argv[1];
      argv++, argc--;
    } else if (strcmp(argv[0], "--log") == 0) {
      do_log = 1;
    } else {
      fatal_error(2, "Invalid option: %s\n", argv[0]);
    }
    argv++, argc--;
  }

  if (!db_file)
    fatal_error(2, "No database file specified in CHRONICLE_DB environment "
                "variable or in --db parameter");
}

static void cancel_command(int64_t id) {
  int i;
  pthread_mutex_lock(&active_queries_mutex);
  for (i = 0; i < MAX_QUERIES; ++i) {
    QueryThread* t = active_queries[i];
    if (t && t->id == id) {
      t->cancelled = 1;
      active_queries[i] = NULL;
      break;
    }
  }
  pthread_mutex_unlock(&active_queries_mutex);
  /* we ignore cancellation of unknown queries */
}

static void info_command(QueryThread* q, JSON_Value* v) {
  JSON_Builder builder;
  static const char* archs[2] = { "x86", "amd64" };
  
  JSON_builder_init_object(&builder);
  if (db.header.architecture <= CH_ARCH_AMD64) {
    JSON_append_string(&builder, "arch", archs[db.header.architecture]);
  }
  JSON_append_string(&builder, "endian",
                     db.header.is_little_endian ? "little" : "big");
  JSON_append_int(&builder, "endTStamp", db.header.end_tstamp);
  JSON_open_array(&builder, "maps");
  JSON_append_string(&builder, NULL, "INSTR_EXEC");
  JSON_append_string(&builder, NULL, "MEM_WRITE");
  JSON_append_string(&builder, NULL, "ENTER_SP");
  JSON_append_string(&builder, NULL, "MEM_MAP");
  if (db.header.have_mem_reads) {
    JSON_append_string(&builder, NULL, "MEM_READ");
  }
  JSON_close_array(&builder);
  complete_work(q, 0, &builder);
}

/**
 * The query is created with one unit of work in progress_max. This
 * ensures it won't be torn down until the corner calls complete_work with
 * that one unit.
 */
static QueryThread* create_query(int64_t id) {
  QueryThread* q = safe_malloc(sizeof(QueryThread));
  int retry = 1;
  int i;

  q->id = id;
  pthread_mutex_init(&q->mutex, NULL);
  q->progress_max = 1;
  q->progress = 0;
  q->cancelled = 0;
  q->sent_termination = 0;

  pthread_mutex_lock(&active_queries_mutex);
  while (retry) {
    for (i = 0; i < MAX_QUERIES; ++i) {
      if (!active_queries[i]) {
                q->index = i;
                active_queries[i] = q;
                retry = 0;
                break;
      }
    }
    if (retry) {
      pthread_cond_wait(&active_queries_condition, &active_queries_mutex);
    }
  }
  pthread_mutex_unlock(&active_queries_mutex);
  return q;
}

void add_work(QueryThread* q, int work_amount) {
  pthread_mutex_lock(&q->mutex);
  q->progress_max += work_amount;
  pthread_mutex_unlock(&q->mutex);
}

void spawn_work(QueryThread* q, CH_ThreadProc fun, void* closure,
                int closure_size, int work_amount) {
  void* cl = safe_malloc(closure_size);
  memcpy(cl, closure, closure_size);

  add_work(q, work_amount);
  run_on_thread(fun, cl);
}

typedef struct {
  const char* name;
  uint64_t    value;
} StringFlag;
static uint64_t convert_string_array_to_flags(QueryThread* q, StringFlag* flags,
                                              JSON_Value* array) {
  int i, j;
  uint64_t result = 0;
  JSON_Value* avals = array->v.a;
  for (i = 0; avals[i].type != JSON_INVALID; ++i) {
    const char* s;
    if (avals[i].type != JSON_STRING) {
      debugger_warning(q, "bad.JSON.type.for.flag",
          "Array index %d had wrong type %d (expected string flag)", i, avals[i].type);
      continue;
    }
    
    s = avals[i].v.s;
    for (j = 0; flags[j].name; ++j) {
      if (strcmp(flags[j].name, s) == 0) {
        result |= flags[j].value;
        break;
      }
    }
    if (!flags[j].name) {
      debugger_warning(q, "bad.JSON.flag",
          "Array index %d had unknown flag %s", i, s);
    }
  }
  return result;
}

static const char* convert_flag_to_string(StringFlag* flags, uint64_t flag) {
  int i;
  for (i = 0; flags[i].name; ++i) {
    if (flags[i].value == flag)
      return flags[i].name;
  }
  return NULL;
}

static StringFlag kind_flag_strings[] = {
  { "variable", AUTOCOMPLETE_KIND_GLOBAL_VARIABLE },
  { "function", AUTOCOMPLETE_KIND_GLOBAL_FUNCTION },
  { "type", AUTOCOMPLETE_KIND_GLOBAL_TYPE },
  { NULL, 0 }
};

static void autocomplete_command(QueryThread* q, JSON_Value* v) {
  JSON_Value* prefix =
    check_field_of_type(q, v, "command", "prefix", JSON_STRING);
  JSON_Value* casesensitive =
    check_optional_field_of_type(q, v, "command", "caseSensitive", JSON_TRUE);
  JSON_Value* from =
    check_optional_field_of_type(q, v, "command", "from", JSON_INT);
  JSON_Value* desiredcount =
    check_optional_field_of_type(q, v, "command", "desiredCount", JSON_INT);
  JSON_Value* kinds =
    check_optional_field_of_type(q, v, "command", "kinds", JSON_ARRAY);
  int i;
  const char* str;
  CH_DbgCompletionKind kind_mask;
  CH_DbgCompletionResult result;

  if (!prefix)
    return;

  kind_mask = (CH_DbgCompletionKind)
      (kinds ? convert_string_array_to_flags(q, kind_flag_strings, kinds)
       : AUTOCOMPLETE_KIND_GLOBAL_TYPE | AUTOCOMPLETE_KIND_GLOBAL_VARIABLE
         | AUTOCOMPLETE_KIND_GLOBAL_FUNCTION);
  result =
    dbg_auto_complete_global_name(q, kind_mask, prefix->v.s,
                                  casesensitive != NULL,
                                  from ? from->v.i : 0,
                                  desiredcount ? desiredcount->v.i : 0x7FFFFFFF);

  if (result.match_count == 0) {
    complete_work(q, 0, NULL);
    return;
  }

  /* there's already one unit of work assigned to this query */
  add_work(q, result.match_count);

  str = result.match_names;
  for (i = 0; i < result.match_count; ++i) {
    JSON_Builder builder;
  
    JSON_builder_init_object(&builder);
    JSON_append_string(&builder, "name", str);
    str += strlen(str) + 1;
    JSON_append_string(&builder, "kind",
      convert_flag_to_string(kind_flag_strings, result.match_kinds[i]));
    if (i == 0) {
      JSON_append_int(&builder, "totalMatches", result.total_matches);
    }
    complete_work(q, 1, &builder);
  }
  safe_free(result.match_kinds);
  safe_free(result.match_names);
}

static void lookup_global_functions_command(QueryThread* q, JSON_Value* v) {
  JSON_Value* name = check_field_of_type(q, v, "command", "name", JSON_STRING);
  JSON_Builder builder;

  if (!name)
    return;

  add_work(q, 1);  
  JSON_builder_init_array(&builder);
  dbg_lookup_global_functions(q, &builder, name->v.s);
  complete_work(q, 1, &builder);
}

static int            num_builtin_maps = 0;
static CH_EffectMapReader builtin_maps[4];

CH_EffectMapReader* get_builtin_write_map() {
  return &builtin_maps[1];
}

static int compare_ranges_by_addr(const void* v1, const void* v2) {
  const CH_Range* r1 = (const CH_Range*)v1;
  const CH_Range* r2 = (const CH_Range*)v2;
  
  if (r1->start < r2->start)
    return -1;
  if (r1->start > r2->start)
    return 1;
  return 0;
}

static CH_Range* build_ranges(QueryThread* q, JSON_Value* ranges, uint32_t* num_ranges) {
  int i, pt, range_count;
  CH_Range* range_list;

  for (i = 0; ranges->v.a[i].type != JSON_INVALID; ++i) {
    JSON_Value* v = &ranges->v.a[i];
    if (v->type != JSON_OBJECT) {
      debugger_error(q, "bad.range.in.ranges", "Range in 'ranges' array is not an object");
      return NULL;
    }
  }

  range_count = i;
  if (range_count < 1) {
    debugger_error(q, "empty.ranges", "'ranges' array is empty");
    return NULL;
  }
  
  range_list = safe_malloc(sizeof(CH_Range)*i);
  for (i = 0; ranges->v.a[i].type != JSON_INVALID; ++i) {
    JSON_Value* v = &ranges->v.a[i];
    JSON_Value* start = check_field_of_type(q, v, "range", "start", JSON_INT);
    JSON_Value* length = check_field_of_type(q, v, "range", "length", JSON_INT);
    if (!start || !length) {
      safe_free(range_list);
      return NULL;
    }
    range_list[i].start = start->v.i;
    range_list[i].length = length->v.i;
  }
  
  /* sort ranges and merge overlapping ranges */
  qsort(range_list, range_count, sizeof(CH_Range), compare_ranges_by_addr);
  
  pt = 0;
  for (i = 1; i < range_count; ++i) {
    if (range_list[pt].start + range_list[pt].length >= range_list[i].start) {
      /* merge overlapping (or just adjacent) range i into pt */
      range_list[pt].length = range_list[i].start + range_list[i].length
          - range_list[pt].start;
    } else {
      ++pt;
      range_list[pt] = range_list[i];
    }
  }

  *num_ranges = pt + 1;
  return safe_realloc(range_list, (pt + 1)*sizeof(CH_Range));
}

static int read_mem_callback(void* closure, QueryThread* q, CH_EffectMapReader* reader,
    CH_TStamp tstamp, CH_Address start_addr, CH_Address end_addr,
    CH_EffectScanResult result, void* data) {
  if (result == ACCESS_NORMAL ||
      !get_address_map_entries()[*(uint32_t*)data].contents_unchanged) {
    uintptr_t len = end_addr - start_addr;
    JSON_Builder builder;
    JSON_builder_init_object(&builder);
    JSON_append_int(&builder, "start", start_addr);
    JSON_append_int(&builder, "length", len);
    if (result == ACCESS_NORMAL) {
      JSON_append_hex_string(&builder, "bytes", data, len);
    } else {
      void* buf = safe_malloc(len);
      if (obtain_memory_contents_from_mmap_callback(q, start_addr, end_addr, data, buf)) {
        JSON_append_hex_string(&builder, "bytes", buf, len);
      }
      safe_free(buf);
    }
    complete_work(q, 0, &builder);
  }
  return 1;
}

static void read_mem_command(QueryThread* q, JSON_Value* v) {
  JSON_Value* tstamp = check_field_of_type(q, v, "command", "TStamp", JSON_INT);
  JSON_Value* ranges = check_field_of_type(q, v, "command", "ranges", JSON_ARRAY);
  CH_Range* range_list;
  uint32_t num_ranges;
  
  if (!tstamp || !ranges)
    return;

  range_list = build_ranges(q, ranges, &num_ranges);
  if (!range_list)
    return;

  effect_map_reader_do_scan(&builtin_maps[1], q, 0, tstamp->v.i, range_list, num_ranges,
                       MODE_FIND_FIRST_COVER, -1, 0, read_mem_callback,
                       NULL, NULL);
}

typedef struct {
  const char* name;
  uint8_t     index;
} RegMap;
#ifdef CH_X86
static RegMap register_map[] = {
  {"thread", CH_REG_THREAD},
#if __WORDSIZE == 32
  {"pc", CH_REG_PC},
  {"eax", 0}, {"ecx", 1}, {"edx", 2}, {"ebx", 3},
  {"esp", 4}, {"ebp", 5}, {"esi", 6}, {"edi", 7},
#else
  {"pc", CH_REG_PC},
  {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3},
  {"rsp", 4}, {"rbp", 5}, {"rsi", 6}, {"rdi", 7},
  {"r8",  8}, {"r9" , 9}, {"r10", 10},{"r11", 11},
  {"r12", 12},{"r13", 13},{"r14", 14},{"r15", 15},
#endif
  {"fp0", CH_X86_FP_REGS},  {"fp1", CH_X86_FP_REGS+1},
  {"fp2", CH_X86_FP_REGS+2},{"fp3", CH_X86_FP_REGS+3},
  {"fp4", CH_X86_FP_REGS+4},{"fp5", CH_X86_FP_REGS+5},
  {"fp6", CH_X86_FP_REGS+6},{"fp7", CH_X86_FP_REGS+7},
  {"fptop", CH_X86_FPTOP_REG},
  {"xmm0", CH_X86_SSE_REGS},  {"xmm1", CH_X86_SSE_REGS+1},
  {"xmm2", CH_X86_SSE_REGS+2},{"xmm3", CH_X86_SSE_REGS+3},
  {"xmm4", CH_X86_SSE_REGS+4},{"xmm5", CH_X86_SSE_REGS+5},
  {"xmm6", CH_X86_SSE_REGS+6},{"xmm7", CH_X86_SSE_REGS+7},
#if __WORDSIZE == 64  
  {"xmm8", CH_X86_SSE_REGS+8},  {"xmm9", CH_X86_SSE_REGS+9},
  {"xmm10", CH_X86_SSE_REGS+10},{"xmm11", CH_X86_SSE_REGS+11},
  {"xmm12", CH_X86_SSE_REGS+12},{"xmm13", CH_X86_SSE_REGS+13},
  {"xmm14", CH_X86_SSE_REGS+14},{"xmm15", CH_X86_SSE_REGS+15},
#endif
  {0, 0}
};
#else
#error "Only x86/AMD64 supported at this time"
#endif

static const char* get_register_name(int reg) {
  int i;
  for (i = 0; register_map[i].name; ++i) {
    if (register_map[i].index == reg)
      return register_map[i].name;
  }
  return NULL;
}

static int convert_bits_to_bytes(QueryThread* q, const char* name,
                                 int64_t v, uint8_t* bytes) {
  switch (v) {
    case 8:
    case 16:
    case 32:
    case 64:
    case 128:
      *bytes = v/8;
      return 1;
    default:
      debugger_error(q, "bad.register.bits.value.in.command",
                     "Value of '%s' should be an integer number of bits, is %lld",
                     name, (long long)v);
      return 0;
  }
}

typedef struct {
  uint8_t num_set;
  uint8_t desired_bytes[CH_REG_MAX + 1];
} ReadRegClosure;

static int regread_callback(void* callback_closure,
  QueryThread* query, uint8_t reg, uint8_t bytes, void* value) {
  ReadRegClosure* cl = callback_closure;
  JSON_Builder builder;
  int i;
  
  JSON_builder_init_object(&builder);
  if (bytes > cl->desired_bytes[reg]) {
    /* XXX assumes little endian */
    bytes = cl->desired_bytes[reg];
  }
  for (i = 0; ; ++i) {
    if (register_map[i].index == reg) {
      /* byteswap from little-endian to big-endian ... assumes we are little-
         endian! */
      JSON_append_hex_string_byteswapped(&builder, register_map[i].name,
                                         value, bytes);
      break;
    }
  }
  cl->num_set--;
  return complete_work(query, 1, &builder);
}

static void read_reg_command(QueryThread* q, JSON_Value* v) {
  JSON_Value* tstamp = check_field_of_type(q, v, "command", "TStamp", JSON_INT);
  int i;
  ReadRegClosure cl;

  if (!tstamp)
    return;

  cl.num_set = 0;
  memset(&cl.desired_bytes, 0, sizeof(cl.desired_bytes));
  for (i = 0; register_map[i].name; ++i) {
    JSON_Value* r = JSON_get_field(v, register_map[i].name);
    if (r) {
      if (r->type != JSON_INT) {
        debugger_error(q, "bad.register.bits.in.command",
                       "Value of '%s' should be an integer number of bits",
                       register_map[i].name);
        return;
      }
      if (!convert_bits_to_bytes(q, register_map[i].name, r->v.i,
                                 &cl.desired_bytes[register_map[i].index]))
        return;
      ++cl.num_set;
    }
  }
  
  if (!cl.num_set) {
    memset(cl.desired_bytes, 128/8, CH_REG_MAX + 1);
    cl.num_set = sizeof(register_map)/sizeof(register_map[0]) - 1;
  }

  add_work(q, cl.num_set);
  reg_read(q, tstamp->v.i, cl.desired_bytes, regread_callback, &cl);
}

static void find_SP_greater_than_command(QueryThread* q, JSON_Value* v) {
  JSON_Value* beginTStamp = check_field_of_type(q, v, "command", "beginTStamp", JSON_INT);
  JSON_Value* endTStamp = check_field_of_type(q, v, "command", "endTStamp", JSON_INT);
  JSON_Value* threshold = check_field_of_type(q, v, "command", "threshold", JSON_INT);
  JSON_Value* thread = check_field_of_type(q, v, "command", "thread", JSON_INT);
  CH_TStamp result;

  if (!beginTStamp || !endTStamp || !threshold || !thread)
    return;

  add_work(q, 1);
  result =
    reg_scan_for_SP_greater_than(q, beginTStamp->v.i, endTStamp->v.i,
                                 thread->v.i, threshold->v.i);
  if (result && result < endTStamp->v.i) {
    JSON_Builder builder;
    JSON_builder_init_object(&builder);
    JSON_append_int(&builder, "TStamp", result);
    complete_work(q, 1, &builder);
  } else {
    complete_work(q, 1, NULL);
  }
}

static int scan_callback(void* closure, QueryThread* q, CH_EffectMapReader* reader,
    CH_TStamp tstamp, CH_Address start_addr, CH_Address end_addr,
    CH_EffectScanResult result, void* data) {
  JSON_Builder builder;
  JSON_builder_init_object(&builder);

  JSON_append_int(&builder, "TStamp", tstamp);
  JSON_append_int(&builder, "start", start_addr);
  JSON_append_int(&builder, "length", end_addr - start_addr);
  if (result == ACCESS_MMAP) {
    CH_DBAddrMapEntry* entry = &get_address_map_entries()[*(uint32_t*)data];
    JSON_append_string(&builder, "type", "mmap");
    if (entry->filename_fileloc) {
      char* filename =
        db_read_alloc(get_db(), entry->filename_fileloc, entry->filename_len);
      JSON_append_stringf(&builder, "filename", "%.*s", entry->filename_len, filename);
      safe_free(filename);
    }
    if (entry->contents_from_file) {
      JSON_append_int(&builder, "offset",
                      entry->offset + (start_addr - entry->address));
    }
    JSON_append_boolean(&builder, "mapped", entry->is_mapped);
    JSON_append_boolean(&builder, "read", entry->is_read);
    JSON_append_boolean(&builder, "write", entry->is_write);
    JSON_append_boolean(&builder, "execute", entry->is_execute);
  } else {
    JSON_append_string(&builder, "type", "normal");
    if (reader && !strcmp(effect_map_reader_get_name(reader), "MEM_WRITE")) {
      JSON_append_hex_string(&builder, "bytes", data, end_addr - start_addr);
    }
  }

  complete_work(q, 0, &builder);
  return 1;
}

static void scan_memory_map(QueryThread* q, CH_TStamp begin_tstamp,
    CH_TStamp end_tstamp, CH_EffectScanMode mode, int direction, CH_Range* range_list,
    uint32_t num_ranges) {
  while (num_ranges > 0) {
    CH_MemMapHistory* h = find_nearest_memory_map_history_for(range_list->start);
    CH_Address start = range_list->start;
    CH_Address end = start + range_list->length;
    int i;
    if (!h)
      return;
    if (h->start >= end) {
      --num_ranges;
      ++range_list;
      continue;
    }
    
    if (h->start > start) {
      start = h->start;
    }
    if (h->end < end) {
      end = h->end;
    }
    
    for (i = 0; i < h->num_map_operations; ++i) {
      CH_DBAddrMapEntry* e = &get_address_map_entries()[h->map_operations[i]];
      if (e->tstamp >= begin_tstamp && e->tstamp < end_tstamp) {
        scan_callback(NULL, q, NULL, e->tstamp, start, end, ACCESS_MMAP,
                      &h->map_operations[i]);
      }
    }
    
    range_list->start = end;
    range_list->length -= (end - start);
    if (range_list->length == 0) {
      --num_ranges;
      ++range_list;
    }
  }
}

static void scan_command(QueryThread* q, JSON_Value* v) {
  JSON_Value* map = check_field_of_type(q, v, "command", "map", JSON_STRING);
  JSON_Value* beginTStamp =
    check_field_of_type(q, v, "command", "beginTStamp", JSON_INT);
  JSON_Value* endTStamp =
    check_field_of_type(q, v, "command", "endTStamp", JSON_INT);
  JSON_Value* ranges =
    check_field_of_type(q, v, "command", "ranges", JSON_ARRAY);
  JSON_Value* termination =
    check_optional_field_of_type(q, v, "command", "termination", JSON_STRING);
  int i;
  CH_EffectScanMode mode;
  int direction;
  CH_TStamp begin_tstamp, end_tstamp;
  CH_Range* range_list;
  uint32_t num_ranges;
  CH_EffectMapReader* r;

  if (!map || !beginTStamp || !endTStamp || !ranges)
    return;

  begin_tstamp = beginTStamp->v.i;
  end_tstamp = endTStamp->v.i;

  mode = MODE_FIND_ALL;
  direction = 1;
  if (termination) {
    if (JSON_is_string(termination, "findFirst")) {
      mode = MODE_FIND_FIRST_ANY;
    } else if (JSON_is_string(termination, "findLast")) {
      mode = MODE_FIND_FIRST_ANY;
      direction = -1;
    } else if (JSON_is_string(termination, "findFirstCover")) {
      mode = MODE_FIND_FIRST_COVER;
      direction = 1;
    } else if (JSON_is_string(termination, "findLastCover")) {
      mode = MODE_FIND_FIRST_COVER;
      direction = -1;
    } else {
      debugger_warning(q, "bad.termination.in.command", "Unknown termination flag");
    }
  }
  
  range_list = build_ranges(q, ranges, &num_ranges);
  if (!range_list)
    return;

  if (JSON_is_string(map, "MEM_MAP")) {
    scan_memory_map(q, begin_tstamp, end_tstamp, mode, direction, range_list, num_ranges);
    safe_free(range_list);
    return;
  }
  
  r = NULL;
  for (i = 0; i < num_builtin_maps; ++i) {
    if (JSON_is_string(map, effect_map_reader_get_name(&builtin_maps[i]))) {
      r = &builtin_maps[i];
      break;
    }
  }
  if (!r) {
    debugger_error(q, "bad.map.in.command", "Unknown map name");
    safe_free(range_list);
    return;
  }
  
  effect_map_reader_do_scan(r, q, begin_tstamp, end_tstamp, range_list, num_ranges,
                       mode, direction, 0, scan_callback, NULL, NULL);
}

static void find_source_info_command(QueryThread* q, JSON_Value* v) {
  JSON_Value* tstamp = check_field_of_type(q, v, "command", "TStamp", JSON_INT);
  JSON_Value* address = check_field_of_type(q, v, "command", "address", JSON_INT);
  JSON_Builder builder;
  CH_DbgSourceInfo result;

  if (!tstamp || !address)
    return;

  result = dbg_get_source_info(q, tstamp->v.i, address->v.i);

  add_work(q, 1);
  
  JSON_builder_init_object(&builder);
  if (result.filename) {
    JSON_append_string(&builder, "filename", result.filename);
    JSON_append_int(&builder, "startLine",   result.start_line);
    JSON_append_int(&builder, "startColumn", result.start_column);
    if (result.end_line && result.end_column) {
      JSON_append_int(&builder, "endLine",   result.end_line);
      JSON_append_int(&builder, "endColumn", result.end_column);
    }
  }

  complete_work(q, 1, &builder);
}

static void find_containing_function_command(QueryThread* q, JSON_Value* v) {
  JSON_Value* tstamp = check_field_of_type(q, v, "command", "TStamp", JSON_INT);
  JSON_Value* address = check_field_of_type(q, v, "command", "address", JSON_INT);
  JSON_Builder builder;

  if (!tstamp || !address)
    return;

  add_work(q, 1);
  JSON_builder_init_array(&builder);
  dbg_get_container_function(q, &builder, tstamp->v.i, address->v.i);
  complete_work(q, 1, &builder);
}

typedef int (* GetVariables)(QueryThread* q, JSON_Builder* builder, CH_TStamp tstamp);

static void get_variables_command(QueryThread* q, JSON_Value* v, GetVariables gv) {
  JSON_Value* tstamp = check_field_of_type(q, v, "command", "TStamp", JSON_INT);
  JSON_Builder builder;

  if (!tstamp)
    return;

  add_work(q, 1);
  JSON_builder_init_array(&builder);
  gv(q, &builder, tstamp->v.i);
  complete_work(q, 1, &builder);
}

static void get_parameters_command(QueryThread* q, JSON_Value* v) {
  get_variables_command(q, v, dbg_get_params);
}

static void get_locals_command(QueryThread* q, JSON_Value* v) {
  get_variables_command(q, v, dbg_get_locals);
}

static void append_location_piece(QueryThread* q, JSON_Builder* builder,
                                  CH_DbgValuePiece* p,
                                  intptr_t value_bit_offset) {
  const char* type;
  
  JSON_open_object(builder, NULL);
  switch (p->type) {
    case CH_PIECE_CONSTANT:
      type = "constant";
      JSON_append_hex_string(builder, "data", (uint8_t*)&p->source, sizeof(p->source));
      break;
    case CH_PIECE_MEMORY:
      type = "memory";
      JSON_append_int(builder, "address", p->source);
      JSON_append_int(builder, "addressBitOffset", p->source_offset_bits);
      break;
    case CH_PIECE_REGISTER:
      type = "register";
      JSON_append_string(builder, "register", get_register_name(p->source));
      JSON_append_int(builder, "registerBitOffset", p->source_offset_bits);
      break;
    case CH_PIECE_UNDEFINED:
      type = "undefined";
      break;
    case CH_PIECE_ERROR:
      type = "error";
      break;
    default:
      debugger_error(q, "unknown.location.piece.type", "Unknown location piece type %d",
                     p->type);
      JSON_close_object(builder);
      return;
  }
  JSON_append_string(builder, "type", type);
  if (value_bit_offset >= 0) {
    JSON_append_int(builder, "valueBitStart", value_bit_offset);
  }
  JSON_append_int(builder, "bitLength", p->source_size_bits);
  JSON_close_object(builder);
}

typedef struct {
  QueryThread* query;
  JSON_Builder builder;
} GetLocationClosure;

static void get_location_dependency_tracker(void* closure, CH_DbgValuePiece* piece) {
  GetLocationClosure* cl = closure;
  append_location_piece(cl->query, &cl->builder, piece, -1);
}

static void get_location_command(QueryThread* q, JSON_Value* v) {
  JSON_Value* tstamp = check_field_of_type(q, v, "command", "TStamp", JSON_INT);
  JSON_Value* valKey = check_field_of_type(q, v, "command", "valKey", JSON_STRING);
  JSON_Value* typeKey = check_field_of_type(q, v, "command", "typeKey", JSON_STRING);
  GetLocationClosure cl;
  CH_DbgValuePiece* pieces;
  int i;
  uint32_t bit_offset = 0;
  CH_Range* valid_ranges;

  if (!tstamp || !valKey || !typeKey)
    return;

  add_work(q, 1);
  cl.query = q;
  JSON_builder_init_array(&cl.builder);
  pieces = dbg_examine_value(q, tstamp->v.i, valKey->v.s, typeKey->v.s,
                             get_location_dependency_tracker, &cl,
                             &valid_ranges);
  if (!pieces) {
    JSON_builder_done(&cl.builder);
    complete_work(q, 1, NULL);
    return;
  }
  
  for (i = 0; pieces[i].type != CH_PIECE_END; ++i) {
    append_location_piece(q, &cl.builder, &pieces[i], bit_offset);
    bit_offset += pieces[i].source_size_bits;
  }
  
  if (valid_ranges) {
    JSON_open_object(&cl.builder, NULL);
    JSON_open_array(&cl.builder, "validForInstructions");
    for (i = 0; valid_ranges[i].length > 0; ++i) {
      JSON_open_object(&cl.builder, NULL);
      JSON_append_int(&cl.builder, "start", valid_ranges[i].start);
      JSON_append_int(&cl.builder, "length", valid_ranges[i].length);
      JSON_close_object(&cl.builder);
    }
    safe_free(valid_ranges);
    JSON_close_array(&cl.builder);
    JSON_close_object(&cl.builder);
  }
  
  safe_free(pieces);
  complete_work(q, 1, &cl.builder);
}

static void lookup_type_command(QueryThread* q, JSON_Value* v) {
  JSON_Value* typekey = check_field_of_type(q, v, "command", "typeKey", JSON_STRING);
  JSON_Builder builder;

  if (!typekey)
    return;

  add_work(q, 1);
  JSON_builder_init_array(&builder);
  dbg_lookup_type(q, &builder, typekey->v.s);
  complete_work(q, 1, &builder);
}

static void lookup_global_type_command(QueryThread* q, JSON_Value* v) {
  JSON_Value* typekey = check_optional_field_of_type(q, v, "command", "typeKey", JSON_STRING);
  JSON_Value* namespace_prefix = check_optional_field_of_type(q, v, "command", "namespacePrefix", JSON_STRING);
  JSON_Value* container_prefix = check_optional_field_of_type(q, v, "command", "cotnainerPrefix", JSON_STRING);
  JSON_Value* name = check_field_of_type(q, v, "command", "name", JSON_STRING);
  JSON_Builder builder;

  if (!name)
    return;

  add_work(q, 1);
  JSON_builder_init_object(&builder);
  dbg_lookup_global_type(q, &builder, name->v.s,
                         namespace_prefix ? namespace_prefix->v.s : NULL,
                         container_prefix ? container_prefix->v.s : NULL,
                         typekey ? typekey->v.s : NULL);
  complete_work(q, 1, &builder);
}

typedef void (* CommandHandler)(QueryThread* query, JSON_Value* command);

typedef struct {
  QueryThread*   query;
  JSON_Value*    v;
  CommandHandler handler;
} PerformCommandClosure;

static void perform_command_thread(void* closure) {
  PerformCommandClosure* cl = closure;
  cl->handler(cl->query, cl->v);
  complete_work(cl->query, 1, NULL);
  safe_free(cl->v);
  safe_free(cl);
}

typedef struct {
  const char*    name;
  CommandHandler handler;
} Command;

static Command commands[] = {
  {"autocomplete", autocomplete_command},
  {"findContainingFunction", find_containing_function_command},
  {"findSourceInfo", find_source_info_command},
  {"findSPGreaterThan", find_SP_greater_than_command},
  {"getLocals", get_locals_command},
  {"getLocation", get_location_command},
  {"getParameters", get_parameters_command},
  {"info", info_command},
  {"lookupGlobalFunctions", lookup_global_functions_command},
  {"lookupGlobalType", lookup_global_type_command},
  {"lookupType", lookup_type_command},
  {"readMem", read_mem_command},
  {"readReg", read_reg_command},
  {"scan", scan_command},
  {NULL, NULL}
};

static void perform_command(JSON_Value* v) {
  JSON_Value* id = JSON_get_field(v, "id");
  JSON_Value* cmd = JSON_get_field(v, "cmd");
  QueryThread* q;

  if (!id)
    debugger_fatal_error(NULL, "no.id.in.command", "No 'id' field in command");
  if (id->type != JSON_INT)
    debugger_fatal_error(NULL, "id.in.command.not.integer", "'id' is not an integer (it's %d)", id->type);

  if (cmd && JSON_is_string(cmd, "cancel")) {
    cancel_command(id->v.i);
    safe_free(v);
    return;
  }

  q = create_query(id->v.i);

  /* actual commands executed here must complete 1 unit of work to
     terminate normally. */
  if (!cmd) {
    debugger_error(q, "no.cmd.in.command", "No 'cmd' field in command");
  } else {
    int i;
    for (i = 0; commands[i].name; ++i) {
      if (!strcmp(commands[i].name, cmd->v.s)) {
        PerformCommandClosure cl = { q, v, commands[i].handler };
        spawn_work(q, perform_command_thread, &cl, sizeof(cl), 0);
        break;
      }
    }
    if (!commands[i].name) {
      debugger_error(q, "cmd.in.command.not.known", "'cmd' is not a known command");
    }
  }
}

void* load_table(const char* section, uint32_t entry_size, uintptr_t* count) {
  CH_DBDirEntry* d = db_directory_lookup(&db, section);
  if (!d)
    debugger_fatal_error(NULL, "db.section.not.found",
                         "Section %s not found in database", section);
  *count = d->length/entry_size;
  return db_read_alloc(&db, d->offset, (uint32_t)d->length);
}

int main(int argc, char** argv) {
  int db_fd;
  char buf[10240];

  pthread_mutex_init(&stdout_lock, NULL);
  pthread_mutex_init(&log_lock, NULL);
  pthread_mutex_init(&active_queries_mutex, NULL);
  pthread_cond_init(&active_queries_condition, NULL);

  init_utils();
  init_threads(30);
  parse_options(argc, argv);
  
  if (do_log) {
    char logfile[1024];
  
    sprintf(logfile, "/tmp/chronicle-log.%d", getpid());
    log_file = fopen(logfile, "w");
    if (!log_file)
      fatal_perror(1, "Cannot open user query log file %s", logfile);
  }
  
  db_fd = open(db_file, O_LARGEFILE | O_RDONLY);
  if (db_fd < 0)
    fatal_perror(1, "Cannot open database file %s", db_file);

  db_init_reader(&db, db_fd);

  reg_log_entries = load_table(CH_SECTION_REG_LOG, sizeof(CH_DBRegLogEntry),
                               &reg_log_entry_count);

  memory_map_init();
  dbg_init();
  reg_init();

  effect_map_reader_init(&builtin_maps[0], "INSTR_EXEC", 0, 0);
  effect_map_reader_init(&builtin_maps[1], "MEM_WRITE", 1, 0);
  effect_map_reader_init(&builtin_maps[2], "ENTER_SP", 0, 0);
  num_builtin_maps = 3;
  if (db.header.have_mem_reads) {
    effect_map_reader_init(&builtin_maps[2], "MEM_READ", 0, 0);
    ++num_builtin_maps;
  }

  buf[sizeof(buf)-1] = 0;
  while (fgets(buf, sizeof(buf), stdin)) {
    JSON_Value* v;
    if (buf[sizeof(buf)-1] != 0)
      fatal_error(99, "Command too large");

    if (log_file) {
      pthread_mutex_lock(&log_lock);
      fputs(buf, log_file);
      fflush(log_file);
      pthread_mutex_unlock(&log_lock);
    }
    
    v = JSON_parse(buf, strlen(buf));
    if (!v)
      fatal_error(88, "Command parse failure");
    perform_command(v);
  }
  
  return 0;
}
