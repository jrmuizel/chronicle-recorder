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

#include "util.h"
#include "debug.h"
#include "debug_internals.h"
#include "debug_dwarf2.h"
#include "reg_reconstruct.h"
#include "effect_map_read.h"
#include "memory_map.h"

#include <pthread.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

/* Global object list */

struct _DebugObject {
  const char*         name;
  CH_DbgDwarf2Object* dwarf_obj;
  uint32_t*           map_events;
  uint32_t            num_map_events;
  int                 fd;
};
static DebugObject* debug_objects;
static uint32_t     debug_object_count;
/* This array is parallel to the array returned by get_address_map_entries(). */
static int32_t*     debug_objects_by_address_map_event;

/* ========== AUTOCOMPLETION ============== */

typedef struct _GlobalSymbolSet GlobalSymbolSet;
struct _GlobalSymbolSet {
  GlobalSymbolSet*    next;
  CH_DbgGlobalSymbol* symbols;
  DebugObject*        defining_object;
  uint32_t            num_symbols;
};
static GlobalSymbolSet* global_symbol_sets;

/* sorted lexicographically by name */
typedef struct {
  uintptr_t            defining_object_offset;
  CH_Address           address;
  const char*          name;
  uint32_t             defining_object:28;
  uint8_t              is_partial:1;
  CH_DbgCompletionKind kind:3;
} GlobalSymbol;
static uint32_t        global_symbol_count;
static GlobalSymbol*   global_symbols;
static pthread_mutex_t global_symbol_mutex;
static pthread_cond_t  global_symbol_condition;

void dbg_add_global_symbols(uint32_t num_symbols, DebugObject* obj,
                            CH_DbgGlobalSymbol* symbols) {
  GlobalSymbolSet* set = safe_malloc(sizeof(GlobalSymbolSet));
  set->next = global_symbol_sets;
  set->defining_object = obj;
  set->num_symbols = num_symbols;
  set->symbols = symbols;
  global_symbol_sets = set;
}

static uint32_t count_symbols() {
  GlobalSymbolSet* set;
  uint32_t count = 0;
  for (set = global_symbol_sets; set; set = set->next) {
    count += set->num_symbols;
  }
  return count;
}

static int compare_uintptr_t(uintptr_t v1, uintptr_t v2) {
  if (v1 < v2)
    return -1;
  if (v1 > v2)
    return 1;
  return 0;
}

static int compare_global_symbols_internal(const GlobalSymbol* s1,
    const GlobalSymbol* s2, int test_dups) {
  int result = strcasecmp(s1->name, s2->name);
  if (result)
    return result;
  result = strcmp(s1->name, s2->name);
  if (result)
    return result;
  result = s1->kind - s2->kind;
  if (result)
    return result;
  result = s1->defining_object - s2->defining_object;
  if (result)
    return result;
  result = s1->is_partial - s2->is_partial;
  if (result)
    return result;
  result = compare_uintptr_t(s1->address, s2->address);
  if (test_dups || result)
    return result;
  return compare_uintptr_t(s1->defining_object_offset, s2->defining_object_offset);
}

static int compare_global_symbols(const void* v1, const void* v2) {
  const GlobalSymbol* s1 = (const GlobalSymbol*)v1;
  const GlobalSymbol* s2 = (const GlobalSymbol*)v2;
  
  return compare_global_symbols_internal(s1, s2, 0);
}

/**
 * Functions that are defined with the same name, defining object, and
 * entry point are considered duplicates and only the first one will be
 * retained.
 */
static uint32_t remove_duplicates(uint32_t count, GlobalSymbol* symbols) {
  uint32_t i;
  uint32_t pt = 0;
  for (i = 1; i < count; ++i) {
    if (compare_global_symbols_internal(&symbols[pt], &symbols[i], 1)) {
      pt++;
      symbols[pt] = symbols[i];
    }
  }
  return pt + 1;
}

static void collect_global_symbols() {
  uint32_t count = count_symbols();
  GlobalSymbol* all_symbols =
      safe_malloc(sizeof(GlobalSymbol)*count);
  GlobalSymbolSet* set;
  GlobalSymbolSet* next;
  uint32_t i;

  count = 0;
  for (set = global_symbol_sets; set; set = next) {
    for (i = 0; i < set->num_symbols; ++i) {
      GlobalSymbol* g = &all_symbols[count + i];
      CH_DbgGlobalSymbol* sym = &set->symbols[i];
      g->name = sym->name;
      g->kind = sym->kind;
      g->is_partial = sym->is_partial;
      g->defining_object = set->defining_object - debug_objects;
      g->defining_object_offset = set->symbols[i].defining_object_offset;
      g->address = sym->address;
    }
    count += set->num_symbols;
    next = set->next;
    safe_free(set->symbols);
    safe_free(set);
  }
  
  qsort(all_symbols, count, sizeof(GlobalSymbol), compare_global_symbols);
  count = remove_duplicates(count, all_symbols);
  all_symbols = safe_realloc(all_symbols, count*sizeof(GlobalSymbol));

  pthread_mutex_lock(&global_symbol_mutex);
  global_symbols = all_symbols;
  global_symbol_count = count;
  pthread_cond_broadcast(&global_symbol_condition);
  pthread_mutex_unlock(&global_symbol_mutex);
}

static void* symbol_loader_thread(void* arg) {
  uint32_t i;
  for (i = 0; i < debug_object_count; ++i) {
    CH_DbgDwarf2Object* dwarf_obj = debug_objects[i].dwarf_obj;
    if (dwarf_obj) {
      dwarf2_load_global_symbols(dwarf_obj, &debug_objects[i]);
    }
  }
  collect_global_symbols();
  return NULL;
}

/* find the first string greater than or equal to 'prefix' */
static uint32_t find_first_match(const char* prefix,
                                 int (* name_cmp)(const char* c1, const char* c2)) {
  uint32_t start = 0;
  uint32_t end = global_symbol_count;
  /* search for the last string less than 'prefix' */
  while (end >= start + 2) {
    uint32_t mid = (start + end)/2;
    if (name_cmp(global_symbols[mid].name, prefix) < 0) {
      start = mid;
    } else {
      end = mid;
    }
  }
  if (start == end)
    return start;
  if (name_cmp(global_symbols[start].name, prefix) < 0) {
    return start + 1;
  } else {
    return start;
  }
}

void dbg_wait_for_global_symbols(QueryThread* q) {
  pthread_mutex_lock(&global_symbol_mutex);
  if (!global_symbols) {
    pthread_cond_wait(&global_symbol_condition, &global_symbol_mutex);
    /* no need to retry the test, the condition can only be signalled after
       the names array has been filled in. */
    /* XXX report progress somehow? */
  }
  pthread_mutex_unlock(&global_symbol_mutex);
}

CH_DbgCompletionResult dbg_auto_complete_global_name(QueryThread* q,
    CH_DbgCompletionKind kinds, const char* prefix, uint8_t case_sensitive,
    int32_t from, int32_t desired_count) {
  CH_DbgCompletionResult result;
  uint32_t first_match;
  CH_GrowBuf matches;
  uint32_t total_match_count;
  uint32_t prefix_len = strlen(prefix);
  uint32_t match_index;
  uint32_t total_chars;
  uint32_t match;

  dbg_wait_for_global_symbols(q);

  init_buf(&matches);
  /* XXX report progress? */
  first_match = find_first_match(prefix, strcasecmp);
  
  /* Collect a list of all matches to be returned. Skip global symbols that
     don't match the search criteria and suppress duplicate name+kind pairs;
     symbols that have the same name and kind but are multiply defined should
     just have one autocomplete result.
     Gather more matches than we really need to get an estimate of the
     total number. */
  match = first_match;
  total_match_count = 0;
  while (match < global_symbol_count &&
         total_match_count < (from + desired_count)*4) {
    GlobalSymbol* m = &global_symbols[match];
    ++match;
    if (strncasecmp(m->name, prefix, prefix_len))
      break;
    if (!(m->kind & kinds))
      continue;
    if (case_sensitive && strncmp(m->name, prefix, prefix_len))
      continue;
    if (total_match_count > 0) {
      GlobalSymbol* prev_match =
          &global_symbols[((uint32_t*)matches.data)[total_match_count - 1]];
      if (strcmp(m->name, prev_match->name) == 0 &&
          m->kind == prev_match->kind)
        continue;
    }
    ensure_buffer_size(&matches, sizeof(uint32_t)*(total_match_count + 1));
    ((uint32_t*)matches.data)[total_match_count] = match - 1;
    total_match_count++;
  }

  result.total_matches = total_match_count;
  result.match_count = total_match_count - from;
  if (result.match_count <= 0) {
    safe_free(matches.data);
    result.match_count = 0;
    result.match_names = NULL;
    result.match_kinds = NULL;
    return result;
  }

  if (result.match_count > desired_count) {
    result.match_count = desired_count;
  }
  total_chars = 0;
  for (match_index = 0; match_index < result.match_count; ++match_index) {
    uint32_t i = ((uint32_t*)matches.data)[match_index + from];
    total_chars += strlen(global_symbols[i].name) + 1;
  }
  result.match_kinds = safe_malloc(sizeof(CH_DbgCompletionKind)*result.match_count);
  result.match_names = safe_malloc(total_chars);
  total_chars = 0;
  for (match_index = 0; match_index < result.match_count; ++match_index) {
    uint32_t i = ((uint32_t*)matches.data)[match_index + from];
    uint32_t len = strlen(global_symbols[i].name) + 1;
    result.match_kinds[match_index] = global_symbols[i].kind;
    memcpy(result.match_names + total_chars, global_symbols[i].name, len);
    total_chars += len;
  }
  safe_free(matches.data);
  return result;
}

static int case_sensitive_cmp(const char* c1, const char* c2) {
  int result = strcasecmp(c1, c2);
  if (result)
    return result;
  return strcmp(c1, c2);
}

static void output_compilation_unit_info(CH_DbgDwarf2CompilationUnitInfo* info,
    JSON_Builder* builder) {
  if (info->language) {
    JSON_append_string(builder, "language", info->language);
  }
  if (info->compilation_unit) {
    JSON_append_string(builder, "compilationUnit", info->compilation_unit);
  }
  if (info->compilation_unit_dir) {
    JSON_append_string(builder, "compilationUnitDir", info->compilation_unit_dir);
  }    
}

static void append_value_key(JSON_Builder* builder, const char* field,
                             DebugObject* defining_object, uintptr_t context_offset,
                             uintptr_t offset) {
  if (!offset)
    return;
  JSON_append_stringf(builder, field, "V%x_%llx_%llx",
                      defining_object - debug_objects,
                      (unsigned long long)context_offset,
                      (unsigned long long)offset);
}

static void append_type_key(JSON_Builder* builder, const char* field,
                            DebugObject* defining_object, uintptr_t type_offset) {
  if (!type_offset)
    return;
  JSON_append_stringf(builder, field, "T%x_%llx",
                      defining_object - debug_objects,
                      (unsigned long long)type_offset);
}

static int crack_hex_integer(QueryThread* query, const char** key, uint64_t* out) {
  uint64_t r = 0;
  const char* s = *key;
  for (;;) {
    char ch = toupper(*s);
    
    if (ch >= '0' && ch <= '9') {
      r *= 16;
      r += ch - '0';
    } else if (ch >= 'A' && ch <= 'F') {
      r *= 16;
      r += ch - 'A' + 10;
    } else {
      break;
    }
    s++;
  }
  if (s == *key) {
    debugger_error(query, "bad.hex", "Expected hexadecimal character in %s", *key);
    return 0;
  }
  
  if (s[0] == '_') {
    s++;
  }
  *key = s;
  *out = r;
  return 1;
}

static DebugObject* crack_defining_object(QueryThread* query, const char** key) {
  uint64_t index;
  if (!crack_hex_integer(query, key, &index))
    return NULL;
  if (index >= debug_object_count || !debug_objects[index].dwarf_obj) {
    debugger_error(query, "bad.debug.obj", "Debug object index %lld is invalid",
                   (long long)index);
  }
  return &debug_objects[index];
}

static uintptr_t crack_offset(QueryThread* query, const char** key) {
  uint64_t offset;
  if (!crack_hex_integer(query, key, &offset))
    return 0;
  if ((uintptr_t)offset != offset) {
    debugger_error(query, "bad.offset", "Debug object offset %lld is invalid",
                   (long long)offset);
  }
  return (uintptr_t)offset;
}

static int crack_value_key(QueryThread* query, const char* key,
                           DebugObject** defining_object, uintptr_t* context_offset,
                           uintptr_t* offset) {
  if (key[0] != 'V') {
    debugger_error(query, "not.value.key",
                   "valkey %s is not a value key", key);
    return 0;
  }
  ++key;
  
  *defining_object = crack_defining_object(query, &key);
  if (!*defining_object)
    return 0;
  *context_offset = crack_offset(query, &key);
  if (!*context_offset != 0)
    return 0;
  *offset = crack_offset(query, &key);
  return *offset != 0;
}

static int crack_type_key(QueryThread* query, const char* key,
                          DebugObject** defining_object, uintptr_t* type_offset) {
  if (key[0] != 'T') {
    debugger_error(query, "not.type.key",
                   "typekey %s is not a type key", key);
    return 0;
  }
  ++key;
  
  *defining_object = crack_defining_object(query, &key);
  if (!*defining_object)
    return 0;
  *type_offset = crack_offset(query, &key);
  return *type_offset != 0;
}

static void output_function_object(DebugObject* defining_object,
    uintptr_t defining_object_offset, CH_DBAddrMapEntry* map_event,
    CH_DbgDwarf2FunctionInfo* info, JSON_Builder* builder) {
  /* translate file address to virtual address(es) and compute the lifetime
     of each mapping */
  JSON_open_object(builder, NULL);

  if (info->entry_point) {
    CH_Address virtual_addr =
      info->entry_point - map_event->offset + map_event->address;
    CH_MemMapHistory* history = find_memory_map_history_for(virtual_addr);
    CH_MemMapInfo mmap_info = get_memory_map_info_for(history, map_event->tstamp);
    CH_TStamp end_tstamp = mmap_info.unmap_operation
        ? mmap_info.unmap_operation->tstamp : get_db()->header.end_tstamp;

    JSON_append_int(builder, "entryPoint", virtual_addr);
    JSON_append_int(builder, "beginTStamp", map_event->tstamp);
    JSON_append_int(builder, "endTStamp", end_tstamp);
    append_type_key(builder, "typeKey", defining_object, info->type_offset);
  }
  if (info->prologue_end) {
    CH_Address virtual_addr =
      info->prologue_end - map_event->offset + map_event->address;
    JSON_append_int(builder, "prologueEnd", virtual_addr);
  }
  
  if (info->name) {
    JSON_append_stringdup(builder, "name", info->name);
  }
  if (info->namespace_prefix) {
    JSON_append_stringdup(builder, "namespacePrefix", info->namespace_prefix);
  }
  if (info->container_prefix) {
    JSON_append_stringdup(builder, "containerPrefix", info->container_prefix);
  }

  output_compilation_unit_info(&info->cu, builder);
  
  JSON_close_object(builder);
}

int dbg_lookup_global_functions(QueryThread* q, JSON_Builder* builder,
                                const char* name) {
  uint32_t match;

  dbg_wait_for_global_symbols(q);

  match = find_first_match(name, case_sensitive_cmp);
  while (match < global_symbol_count &&
         !strcmp(global_symbols[match].name, name)) {
    GlobalSymbol* g = &global_symbols[match];
    DebugObject* obj = &debug_objects[g->defining_object];
    CH_DbgDwarf2FunctionInfo info;
    
    if (!(g->kind & AUTOCOMPLETE_KIND_GLOBAL_FUNCTION))
      continue;
    if (!dwarf2_lookup_function_info(q, obj->dwarf_obj,
            g->defining_object_offset, DWARF2_FUNCTION_ALL, &info))
      return 0;
    if (info.entry_point) {
      uint32_t i;
      for (i = 0; i < obj->num_map_events; ++i) {
        CH_DBAddrMapEntry* entry = get_address_map_entries() + obj->map_events[i];
        if (entry->offset <= info.entry_point &&
            info.entry_point < entry->offset + entry->length) {
          output_function_object(obj, g->defining_object_offset, entry,
                                 &info, builder);
        }
      }
    }
    safe_free(info.container_prefix);
    safe_free(info.namespace_prefix);
    ++match;
  }
  return 1;
}

static int lookup_global_type_score_symbol(GlobalSymbol* g, DebugObject* obj) {
  if (obj == &debug_objects[g->defining_object_offset])
    return 1;
  return 0;
}

int dbg_lookup_global_type(QueryThread* q, JSON_Builder* builder,
                           const char* name, const char* namespace_prefix,
                           const char* container_prefix, const char* context_typekey) {
  uint32_t match;
  CH_StringBuf full_name;
  char* heap_name;
  GlobalSymbol* best_symbol = NULL;
  DebugObject* context_type_object;
  CH_DbgDwarf2Offset context_type_offset;

  if (!crack_type_key(q, context_typekey, &context_type_object, &context_type_offset))
    return 0;

  dbg_wait_for_global_symbols(q);
  
  stringbuf_init(&full_name);
  if (namespace_prefix) {
    stringbuf_append(&full_name, namespace_prefix);
  }
  if (container_prefix) {
    stringbuf_append(&full_name, container_prefix);
  }
  stringbuf_append(&full_name, name);
  heap_name = stringbuf_finish(&full_name);
  
  match = find_first_match(heap_name, case_sensitive_cmp);
  while (match < global_symbol_count &&
         !strcmp(global_symbols[match].name, heap_name)) {
    GlobalSymbol* g = &global_symbols[match];
    ++match;

    if (g->kind != AUTOCOMPLETE_KIND_GLOBAL_TYPE)
      continue;
    if (g->is_partial)
      continue;

    if (!best_symbol ||
        lookup_global_type_score_symbol(g, context_type_object) >
        lookup_global_type_score_symbol(best_symbol, context_type_object)) {
      best_symbol = g;
    }
  }
 
  if (best_symbol) { 
    append_type_key(builder, "typeKey", &debug_objects[best_symbol->defining_object],
                    best_symbol->defining_object_offset);
  }
  
  safe_free(heap_name);
  return 1;
}

static void translate_virtual_to_file_address(CH_Address virtual_addr,
    CH_TStamp tstamp, CH_Address* file_addr, CH_MemMapInfo* mmap_info) {
  CH_MemMapHistory* history = find_memory_map_history_for(virtual_addr);
  
  *file_addr = 0;
  *mmap_info = get_memory_map_info_for(history, tstamp);
  if (!mmap_info->map_operation)
    return;
  *file_addr = virtual_addr - mmap_info->map_operation->address
      + mmap_info->map_operation->offset;
}

static int get_dwarf2_function_for(QueryThread* q, CH_TStamp tstamp,
                                   CH_Address virtual_addr, DebugObject** obj,
                                   uintptr_t* defining_object_offset,
                                   CH_Address* file_addr,
                                   CH_MemMapInfo* mmap_info) {
  int32_t debug_object_index;

  *defining_object_offset = 0;
  translate_virtual_to_file_address(virtual_addr, tstamp, file_addr, mmap_info);
  
  debug_object_index =
    debug_objects_by_address_map_event[mmap_info->map_operation - 
                                       get_address_map_entries()];
  if (debug_object_index < 0)
    return 1;
  *obj = &debug_objects[debug_object_index];
  
  if (!(*obj)->dwarf_obj)
    return 1;
  
  if (!dwarf2_get_container_function(q, (*obj)->dwarf_obj, *file_addr,
                                     defining_object_offset))
    return 0;
  return 1;
}

int dbg_get_container_function(QueryThread* q, JSON_Builder* builder, CH_TStamp tstamp,
                               CH_Address virtual_addr) {
  CH_DbgDwarf2FunctionInfo info;
  DebugObject* obj;
  uintptr_t defining_object_offset;
  CH_MemMapInfo mmap_info;
  CH_Address file_addr;

  if (!get_dwarf2_function_for(q, tstamp, virtual_addr, &obj,
                               &defining_object_offset, &file_addr, &mmap_info))
    return 0;
  if (!defining_object_offset)
    return 1;

  if (!dwarf2_lookup_function_info(q, obj->dwarf_obj, defining_object_offset,
                                   DWARF2_FUNCTION_ALL, &info))
    return 0;
  output_function_object(obj, defining_object_offset, mmap_info.map_operation,
                         &info, builder);
  return 1;
}

static int cmp_file_names(const void* v1, const void* v2) {
  const char** e1 = (const char**)v1;
  const char** e2 = (const char**)v2; 
  return strcmp(*e1, *e2);
}

static int32_t find_object_with_name(const char* name) {
  int32_t start = 0;
  int32_t end = debug_object_count;
  while (start + 2 <= end) {
    int32_t mid = (start + end)/2;
    if (strcmp(name, debug_objects[mid].name) < 0) {
      end = mid;
    } else {
      start = mid;
    }
  }
  if (start < end && strcmp(name, debug_objects[start].name) == 0)
    return start;
  return -1;
}

static CH_DbgDwarf2Object* load_dwarf2_for(int fd, const char* name) {
  char buf[10240];
  CH_DbgDwarf2Object* obj = dwarf2_load(fd, name);
  if (obj)
    return obj;

  /* fd was closed. Try to open external debug info. */
  snprintf(buf, sizeof(buf), "/usr/lib/debug%s.debug", name);
  buf[sizeof(buf) - 1] = 0;
  fd = open(buf, O_RDONLY);
  if (fd < 0) {
    errno = 0;
    return NULL;
  }
  return dwarf2_load(fd, buf);
}

static char empty_string[] = "";
static void load_all_mmapped_objects() {
  CH_DBAddrMapEntry* all_maps = get_address_map_entries();
  uint32_t all_maps_count = get_address_map_entry_count();
  uint32_t num_map_events = 0;
  uint32_t mapped_file_count = 0;
  DebugObject* mapped_files;
  uint32_t i;
  int32_t* objects = safe_malloc(sizeof(uint32_t)*all_maps_count);
  char** file_names_orig_order = safe_malloc(sizeof(char*)*all_maps_count);
  char** file_names = safe_malloc(sizeof(char*)*all_maps_count);
  uint32_t* map_events;
  
  for (i = 0; i < all_maps_count; ++i) {
    CH_DBAddrMapEntry* map = &all_maps[i];
    objects[i] = -1;
    file_names[i] = empty_string;
    file_names_orig_order[i] = empty_string;
    /* Only consider files where at least part of the file was mapped executable. */
    if (map->is_file && map->filename_fileloc && map->is_execute &&
        !map->suppress_debug_info) {
      int len = map->filename_len;
      char* str = db_read_alloc(get_db(), map->filename_fileloc, len);
      str = safe_realloc(str, len + 1);
      str[len] = 0;
      file_names[i] = str;
      file_names_orig_order[i] = str;
      ++num_map_events;
    }
  }

  qsort(file_names, all_maps_count, sizeof(char*), cmp_file_names);

  for (i = 0; i < all_maps_count; ++i) {
    if (file_names[i] == empty_string)
      continue;
    if (i == 0 || strcmp(file_names[i], file_names[i - 1])) {
      ++mapped_file_count;
    }
  }
  mapped_files = safe_malloc(sizeof(DebugObject)*mapped_file_count);
  map_events = safe_malloc(sizeof(uint32_t)*num_map_events);
  mapped_file_count = 0;
  for (i = 0; i < all_maps_count; ++i) {
    char* name = file_names[i];
    if (name == empty_string)
      continue;
    if (mapped_file_count == 0 ||
        strcmp(name, mapped_files[mapped_file_count - 1].name)) {
      int fd = open(file_names[i], O_RDONLY);
      DebugObject* obj = &mapped_files[mapped_file_count];

      obj->fd = fd;
      obj->name = name;
      obj->dwarf_obj = NULL;
      obj->map_events = map_events;
      obj->num_map_events = 0;
      if (fd < 0) {
        debugger_info(NULL, "debug.file.not.found",
            "File '%s' not found searching for debug info, skipping...", name);
      } else {
        struct stat statbuf;
        if (fstat(fd, &statbuf) < 0) {
          debugger_warning(NULL, "debug.file.not.found",
              "File '%s' could not be stat'ted, skipping...", name);
          close(fd);
        } else if (statbuf.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH)) {
          CH_DbgDwarf2Object* dwarf_obj = load_dwarf2_for(fd, name);
          if (!dwarf_obj) {
            debugger_info(NULL, "debug.file.no.debug.info",
                          "Executable file '%s' does not have debug info", name);
          } else {
            debugger_info(NULL, "debug.file.got.debug.info",
                          "Loaded symbols for '%s'", name);
            obj->dwarf_obj = dwarf_obj;
          }
        }
      }
      ++mapped_file_count;
    }
    ++map_events;
  }
  debug_objects = mapped_files;
  debug_object_count = mapped_file_count;
  
  for (i = 0; i < all_maps_count; ++i) {
    if (file_names_orig_order[i] != empty_string) {
      int32_t index = find_object_with_name(file_names_orig_order[i]);
      if (index < 0) {
        objects[i] = -1;
      } else {
        DebugObject* obj = &debug_objects[index];
        objects[i] = index;
        obj->map_events[obj->num_map_events] = i;
        obj->num_map_events++;
        if (obj->name != file_names_orig_order[i]) {
          safe_free(file_names_orig_order[i]);
        }
      }
    }
  }
  debug_objects_by_address_map_event = objects;
  
  safe_free(file_names_orig_order);
  safe_free(file_names);
}

int dbg_aquire_fd_for_mapped_file(CH_DBAddrMapEntry* e) {
  uint32_t i = e - get_address_map_entries();
  if (debug_objects_by_address_map_event[i] < 0)
    return -1;
  return debug_objects[debug_objects_by_address_map_event[i]].fd;
}

void dbg_release_fd_for_mapped_file(CH_DBAddrMapEntry* e, int fd) {
}

void dbg_init() {
  pthread_t global_symbol_loader;

  load_all_mmapped_objects();
  pthread_create(&global_symbol_loader, NULL, symbol_loader_thread, NULL);
}

static int reg_get_PC_callback(void* closure, QueryThread* q,
                               uint8_t reg, uint8_t bytes, void* value) {
  CH_Address* addr = closure;
  *addr = *(CH_Address*)value;
  return 1;
}

static CH_Address get_virtual_pc_addr(QueryThread* q, CH_TStamp tstamp) {
  CH_Address virtual_pc_addr = 0;
  uint8_t requested_regs[CH_REG_MAX + 1];

  /* get the PC for the given tstamp */
  memset(requested_regs, 0, sizeof(requested_regs));
  requested_regs[CH_REG_PC] = 1;
  reg_read(q, tstamp, requested_regs, reg_get_PC_callback, &virtual_pc_addr);
  return virtual_pc_addr;
}

static int get_function_variables(QueryThread* q, JSON_Builder* builder,
                                  CH_TStamp tstamp,
                                  CH_DbgDwarf2VariableKind kind) {
  DebugObject* obj;
  uintptr_t defining_object_offset;
  CH_MemMapInfo mmap_info;
  CH_DbgDwarf2VariableInfo* results;
  uint32_t i;
  CH_Address file_pc_addr;  
  CH_Address virtual_pc_addr = get_virtual_pc_addr(q, tstamp);
  if (!virtual_pc_addr)
    return 0;

  /* locate the function covering that PC */
  if (!get_dwarf2_function_for(q, tstamp, virtual_pc_addr, &obj,
                               &defining_object_offset, &file_pc_addr, &mmap_info))
    return 0;

  /* get the locals or parameters defined in that function */
  results = dwarf2_get_variables(q, obj->dwarf_obj, defining_object_offset,
                                 file_pc_addr, kind);
  if (!results)
    return 0;

  for (i = 0; results[i].variable_offset; ++i) {
    CH_DbgDwarf2VariableInfo* r = &results[i];
    JSON_open_object(builder, NULL);
    if (r->name) {
      JSON_append_string(builder, "name", r->name);
    }
    append_value_key(builder, "valKey", obj, defining_object_offset, r->variable_offset);
    append_type_key(builder, "typeKey", obj, r->type_offset);
    JSON_close_object(builder);
  }
  safe_free(results);
  return 1;
}

int dbg_get_params(QueryThread* q, JSON_Builder* builder, CH_TStamp tstamp) {
  return get_function_variables(q, builder, tstamp, CH_DWARF2_FORMAL_PARAMETER);
}

int dbg_get_locals(QueryThread* q, JSON_Builder* builder, CH_TStamp tstamp) {
  return get_function_variables(q, builder, tstamp, CH_DWARF2_LOCAL_VARIABLE);
}

typedef struct {
  CH_DbgDependencyCallback tracker;
  void*                    tracker_closure;
  QueryThread*             query;
  
  uint8_t* saved_registers[CH_REG_MAX + 1];
  uint8_t* saved_registers_buf;
} ExaminationClosure;

CH_DbgValuePiece* dbg_examine_value(QueryThread* q, CH_TStamp tstamp,
                                    const char* valkey, const char* typekey,
                                    CH_DbgDependencyCallback dependency_tracker,
                                    void* dependency_tracker_closure,
                                    CH_Range** output_valid_instruction_ranges) {
  ExaminationClosure cl;
  DebugObject* value_object;
  DebugObject* type_object;
  uintptr_t function_offset, variable_offset, type_offset;
  CH_MemMapInfo mmap_info;
  CH_Address file_pc_addr;
  CH_Address virtual_pc_addr = get_virtual_pc_addr(q, tstamp);
  CH_DbgProgramState state;
  CH_DbgValuePiece* pieces;
  
  if (!virtual_pc_addr)
    return NULL;
  
  translate_virtual_to_file_address(virtual_pc_addr, tstamp, &file_pc_addr,
                                    &mmap_info);
  
  if (!crack_value_key(q, valkey, &value_object, &function_offset, &variable_offset))
    return NULL;
  if (!crack_type_key(q, typekey, &type_object, &type_offset))
    return NULL;
    
  if (value_object != type_object) {
    debugger_error(q, "valkey.typekey.mismatch",
                   "Debug object mismatch between valkey %s and typekey %s",
                   valkey, typekey);
    return NULL;
  }
  
  if (!type_object->dwarf_obj) {
    debugger_error(q, "bad.type.key",
                   "Typekey %s refers to object with no debug information");
    return NULL;
  }

  cl.query = q;
  cl.tracker = dependency_tracker;
  cl.tracker_closure = dependency_tracker_closure;
  cl.saved_registers_buf = NULL;
  state.closure = &cl;
  state.tstamp = tstamp;
  /* XXX should we set the size of the last piece, if necessary, from the type? */
  pieces = dwarf2_examine_value(q, value_object->dwarf_obj, function_offset,
                                file_pc_addr, variable_offset,
                                &state, output_valid_instruction_ranges);
  /* translate validity addresses from dwarf file offsets to virtual addresses */
  if (pieces && *output_valid_instruction_ranges) {
    int i;
    CH_DBAddrMapEntry* map_event = mmap_info.map_operation;
    for (i = 0; (*output_valid_instruction_ranges)[i].length > 0; ++i) {
      (*output_valid_instruction_ranges)[i].start +=
        map_event->address - map_event->offset;
    }
  }
  safe_free(cl.saved_registers_buf);
  return pieces;
}

typedef struct {
  ExaminationClosure* outer;
  uint8_t*            result;
  uint8_t*            valid;
  CH_Address          addr;
} DbgReadMemoryClosure;

static int read_memory_callback(void* closure, QueryThread* q, CH_EffectMapReader* reader,
    CH_TStamp tstamp, CH_Address start_addr, CH_Address end_addr,
    CH_EffectScanResult result, void* data) {
  DbgReadMemoryClosure* inner = closure;
  /* take care ... this could be running on multiple threads. We should be OK
     because effect_map_reader_do_scan will not report overlapping events
     in MODE_FIND_FIRST_COVER */
  uintptr_t offset = start_addr - inner->addr;
  uintptr_t len = end_addr - start_addr;
  if (result == ACCESS_NORMAL) {
    memcpy(inner->result + offset, data, len);
    memset(inner->valid + offset, 1, len);
  } else if (!((CH_DBAddrMapEntry*)data)->contents_unchanged) {
    if (obtain_memory_contents_from_mmap_callback(inner->outer->query,
      start_addr, end_addr, data, inner->result + offset)) {
      memset(inner->valid + offset, 1, len);
    }
  }
  return 1;
}

int dbg_read_memory(CH_DbgProgramState* state, CH_Address addr, uint32_t len,
                    uint8_t* result, uint8_t* valid) {
  ExaminationClosure* cl = state->closure;
  CH_Range range = { addr, len };
  DbgReadMemoryClosure inner = { cl, result, valid, addr };
  CH_Semaphore sem;

  memset(valid, 0, len);
  semaphore_init(&sem);
  effect_map_reader_do_scan(get_builtin_write_map(),
                            cl->query, 0, state->tstamp, &range, 1,
                            MODE_FIND_FIRST_COVER, -1, 0, read_memory_callback,
                            &inner, &sem);
  semaphore_wait_for_all_removed(&sem);
  semaphore_destroy(&sem);
  return 1;
}

static int load_registers_callback(void* callback_closure,
  QueryThread* query, uint8_t reg, uint8_t bytes, void* value) {
  ExaminationClosure* cl = callback_closure;
  memcpy(cl->saved_registers[reg], value, bytes);
  return 1;
}    
  
static void ensure_registers_loaded(CH_DbgProgramState* state) {
  ExaminationClosure* cl = state->closure;
  uint8_t* reg_sizes;
  int i;
  int total_size = 0;

  if (cl->saved_registers_buf)
    return;

  reg_sizes = get_register_byte_sizes();
  for (i = 0; i <= CH_REG_MAX; ++i) {
    total_size += reg_sizes[i];
  }
  cl->saved_registers_buf = safe_malloc(total_size);
  total_size = 0;
  for (i = 0; i <= CH_REG_MAX; ++i) {
    cl->saved_registers[i] = cl->saved_registers_buf + total_size;
    total_size += reg_sizes[i];
  }
  
  reg_read(cl->query, state->tstamp, reg_sizes, load_registers_callback, cl);
}
                                        
int dbg_read_reg(CH_DbgProgramState* state, uint8_t reg, uint8_t size,
                 uint8_t* result) {
  ExaminationClosure* cl = state->closure;
  uint8_t* reg_sizes = get_register_byte_sizes();
  
  ensure_registers_loaded(state);
  if (size > reg_sizes[reg]) {
    debugger_error(cl->query, "bad.debug.info.register.overrun",
                   "Debug info requesting non-existent register bytes");
    memset(result, 0, size);
    size = reg_sizes[reg];
  }
  memcpy(result, cl->saved_registers[reg], size);

  if (cl->tracker) {
    CH_DbgValuePiece piece = { CH_PIECE_REGISTER, reg, 0, size*8 };
    cl->tracker(cl->tracker_closure, &piece);
  }

  return 1;
}

static void output_enum_value(void* closure, const char* name, int64_t value) {
  JSON_Builder* builder = closure;
  
  JSON_open_object(builder, NULL);
  if (name) {
    JSON_append_string(builder, "name", name);
  }
  JSON_append_int(builder, "value", value);
  JSON_close_object(builder);
}

typedef struct {
  JSON_Builder* builder;
  DebugObject*  container_object;
} BuilderContainerClosure;

static void output_function_parameter(void* closure, const char* name,
                                      CH_DbgDwarf2Offset type_offset) {
  BuilderContainerClosure* cl = closure;
  
  JSON_open_object(cl->builder, NULL);
  if (name) {
    JSON_append_string(cl->builder, "name", name);
  }
  if (type_offset) {
    append_type_key(cl->builder, "typeKey", cl->container_object, type_offset);
  }
  JSON_close_object(cl->builder);
}

static void output_struct_field(void* closure, const char* name, int64_t byte_offset,
     CH_DbgDwarf2Offset type_offset, uint8_t is_subobject,
     uint8_t is_synthetic, int32_t byte_size, int32_t bit_offset,
     int32_t bit_size) {
  BuilderContainerClosure* cl = closure;
  JSON_Builder* builder = cl->builder;
  
  JSON_open_object(builder, NULL);
  JSON_append_int(builder, "byteOffset", byte_offset);
  append_type_key(builder, "typeKey", cl->container_object, type_offset);
  if (name) {
    JSON_append_string(builder, "name", name);
  }
  if (is_synthetic) {
    JSON_append_simple(builder, "synthetic", JSON_TRUE);
  }
  if (is_subobject) {
    JSON_append_simple(builder, "isSubobject", JSON_TRUE);
  }
  if (bit_offset >= 0) {
    JSON_append_int(builder, "bitOffset", bit_offset);
    JSON_append_int(builder, "bitSize", bit_size);
    JSON_append_int(builder, "byteSize", byte_size);
  }
  JSON_close_object(builder);
}

static int lookup_type_dwarf2(QueryThread* q, JSON_Builder* builder,
    DebugObject* container_object, uintptr_t type_offset) {
  CH_DbgDwarf2TypeInfo info;
  CH_DbgDwarf2Object* dwarf_obj = container_object->dwarf_obj;
  char const* kind;
  
  if (!container_object->dwarf_obj) {
    debugger_error(q, "bad.type.key",
                   "Typekey %s refers to executable with no debug information");
    return 0;
  }

  if (!dwarf2_lookup_type_info(q, dwarf_obj, type_offset, &info))
    return 0;

  JSON_open_object(builder, NULL);
  append_type_key(builder, "typeKey", container_object, type_offset);
  if (info.inner_type_offset && info.kind != CH_TYPE_FUNCTION) {
    append_type_key(builder, "innerTypeKey", container_object,
                    info.inner_type_offset);
  }
  if (info.is_dynamic) {
    JSON_append_simple(builder, "dynamic", JSON_TRUE);
  }
  if (info.is_declaration_only) {
    JSON_append_simple(builder, "partial", JSON_TRUE);
  }
  output_compilation_unit_info(&info.cu, builder);
  if (info.name) {
    JSON_append_stringdup(builder, "name", info.name);
  }
  if (info.namespace_prefix) {
    JSON_append_stringdup(builder, "namespacePrefix", info.namespace_prefix);
    safe_free(info.namespace_prefix);
  }
  if (info.container_prefix) {
    JSON_append_stringdup(builder, "containerPrefix", info.container_prefix);
    safe_free(info.container_prefix);
  }
  if (info.bytes_size >= 0) {
    JSON_append_int(builder, "byteSize", info.bytes_size);
  }
  switch (info.kind) {
    case CH_TYPE_UNKNOWN:
      debugger_error(q, "bad.type.key",
                     "Typekey refers to unknown type");
      return 0;
      
    case CH_TYPE_ANNOTATION: {
      char const* annotation_kind;
      switch (info.annotation_kind) {
        case CH_ANNOTATION_CONST: annotation_kind = "const"; break;
        case CH_ANNOTATION_VOLATILE: annotation_kind = "volatile"; break;
        case CH_ANNOTATION_RESTRICT: annotation_kind = "restrict"; break;
        default:
          debugger_error(q, "bad.type.key",
                         "Typekey refers to annotation of unknown kind");
          return 0;
      }
      JSON_append_string(builder, "annotation", annotation_kind);
      kind = "annotation";
      break;
    }
    
    case CH_TYPE_ARRAY:
      if (info.array_length >= 0) {
        JSON_append_int(builder, "length", info.array_length);
      }
      kind = "array";
      break;
      
    case CH_TYPE_ENUM:
      JSON_open_array(builder, "values");
      if (!dwarf2_iterate_type_enum_values(q, dwarf_obj, type_offset,
                                           output_enum_value, builder))
        return 0;
      JSON_close_array(builder);
      kind = "enum";
      break;
      
    case CH_TYPE_FLOAT:
      kind = "float";
      break;
      
    case CH_TYPE_INT:
      if (info.int_is_signed) {
        JSON_append_simple(builder, "signed", JSON_TRUE);
      }
      kind = "int";
      break;
      
    case CH_TYPE_TYPEDEF:
      kind = "typedef";
      break;      
      
    case CH_TYPE_POINTER:
      if (info.pointer_is_reference) {
        JSON_append_simple(builder, "isReference", JSON_TRUE);
      }
      kind = "pointer";
      break;
      
    case CH_TYPE_FUNCTION: {
      BuilderContainerClosure cl = { builder, container_object };

      kind = "function";
      if (info.inner_type_offset) {
        append_type_key(builder, "resultTypeKey", container_object,
                        info.inner_type_offset);
      }
      JSON_open_array(builder, "parameters");
      if (!dwarf2_iterate_type_function_parameters(q, dwarf_obj, type_offset,
                                                   output_function_parameter, &cl))
        return 0;
      JSON_close_array(builder);
      break;
    }
      
    case CH_TYPE_STRUCT: {
      char const* struct_kind;
      BuilderContainerClosure cl = { builder, container_object };
      
      switch (info.struct_kind) {
        case CH_STRUCT_KIND_STRUCT: struct_kind = "struct"; break;
        case CH_STRUCT_KIND_UNION: struct_kind = "union"; break;
        case CH_STRUCT_KIND_CLASS: struct_kind = "class"; break;
        default:
          debugger_error(q, "bad.type.key",
                         "Typekey refers to struct of unknown kind");
          return 0;
      }
      JSON_append_string(builder, "structKind", struct_kind);
      JSON_open_array(builder, "fields");
      if (!dwarf2_iterate_type_struct_fields(q, dwarf_obj, type_offset,
                                             output_struct_field, &cl))
        return 0;
      JSON_close_array(builder);
      kind = "struct";
      break;
    }
      
    default:
      debugger_error(q, "bad.type.key",
                     "Typekey refers to type of unknown kind");
      return 0;
  }
  JSON_append_string(builder, "kind", kind);
  JSON_close_object(builder);

  return 1;
}

/* Fills in the type information for the given typekey. */
int dbg_lookup_type(QueryThread* q, JSON_Builder* builder, const char* typekey) {
  DebugObject* type_object;
  uintptr_t type_offset;
  
  if (!crack_type_key(q, typekey, &type_object, &type_offset))
    return 0;

  return lookup_type_dwarf2(q, builder, type_object, type_offset);
}
