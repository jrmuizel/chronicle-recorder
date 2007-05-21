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

#include "reg_reconstruct.h"
#include "database.h"
#include "decompression_cache.h"
#include "decompressor.h"
#include "query.h"

#include <memory.h>

#define PTR_BITS (sizeof(void*)*8)

#ifdef CH_X86
#if __WORDSIZE == 64
typedef CH_AMD64Context CH_Context;
#define CH_PTR_LOG2_BYTES 3
#else
typedef CH_X86Context CH_Context;
#define CH_PTR_LOG2_BYTES 2
#endif
#else
#error "Only X86/AMD64 supported at this time"
#endif

static CH_DBRegLogEntry* reg_log_entries;
static uintptr_t reg_log_entry_count;

static CH_DBEffectSetEntry* effect_set_entries;
static uintptr_t effect_set_entry_count;
static uint8_t** effect_set_data;
static pthread_mutex_t effect_set_data_mutex;

static CH_DBCodeInfoEntry* code_info_entries;
static uintptr_t code_info_entry_count;

static uint16_t reg_addr_offset_table[256];
static uint8_t reg_size_table[256];
  
#define NUM_ELEM(a) (sizeof(a)/sizeof(a[0]))

void reg_init(void) {
  CH_Context ctx;
  int i;
  
  reg_log_entries = load_table(CH_SECTION_REG_LOG, sizeof(CH_DBRegLogEntry),
                               &reg_log_entry_count);
  code_info_entries = load_table(CH_SECTION_CODE_INFO, sizeof(CH_DBCodeInfoEntry),
                                 &code_info_entry_count);
  effect_set_entries = load_table(CH_SECTION_EFFECT_SET, sizeof(CH_DBEffectSetEntry),
                                  &effect_set_entry_count);

  effect_set_data = safe_malloc(sizeof(uint8_t*)*effect_set_entry_count);
  memset(effect_set_data, 0, sizeof(uint8_t*)*effect_set_entry_count);
  pthread_mutex_init(&effect_set_data_mutex, NULL);
  
  memset(reg_addr_offset_table, 0, sizeof(reg_addr_offset_table));
  memset(reg_size_table, 0, sizeof(reg_size_table));
  for (i = 0; i < NUM_ELEM(ctx.regs_GP); ++i) {
    reg_addr_offset_table[CH_X86_GP_REGS + i] = (uint8_t*)&ctx.regs_GP[i] - (uint8_t*)&ctx;
    reg_size_table[CH_X86_GP_REGS + i] = sizeof(ctx.regs_GP[i]);
  }
  for (i = 0; i < NUM_ELEM(ctx.regs_FP); ++i) {
    reg_addr_offset_table[CH_X86_FP_REGS + i] = (uint8_t*)&ctx.regs_FP[i] - (uint8_t*)&ctx;
    reg_size_table[CH_X86_FP_REGS + i] = sizeof(ctx.regs_FP[i]);
  }
  for (i = 0; i < NUM_ELEM(ctx.regs_SSE); ++i) {
    reg_addr_offset_table[CH_X86_SSE_REGS + i] = (uint8_t*)&ctx.regs_SSE[i] - (uint8_t*)&ctx;
    reg_size_table[CH_X86_SSE_REGS + i] = sizeof(ctx.regs_SSE[i]);
  }
  reg_addr_offset_table[CH_X86_FPTOP_REG] = (uint8_t*)&ctx.FP_top - (uint8_t*)&ctx;
  reg_size_table[CH_X86_FPTOP_REG] = sizeof(ctx.FP_top);
  
  reg_size_table[CH_REG_PC] = sizeof(ctx.regs_GP[0]);
  reg_size_table[CH_REG_THREAD] = sizeof(uint32_t);
}

uint8_t* get_register_byte_sizes() {
  return reg_size_table;
}

static CH_DBRegLogEntry* find_reg_log_entry_containing(CH_TStamp tstamp) {
  uint32_t start = 0;
  uint32_t end = (uint32_t)reg_log_entry_count;
  
  while (end - start > 1) {
    uint32_t mid = (start + end)/2;
    if (reg_log_entries[mid].first_tstamp <= tstamp) {
      start = mid;
    } else {
      end = mid;
    }
  }

  if (start == end)
    return NULL;  
  if (reg_log_entries[start].first_tstamp <= tstamp)
    return &reg_log_entries[start];
  return NULL;
}

static void* align_pointer(void* p, uint32_t align) {
  return (void*)(((uintptr_t)p + align - 1) & ~((uintptr_t)align - 1));
}

static uint32_t align_size_to_pointer(uint32_t v) {
  return (v + sizeof(CH_Address) - 1) & ~(sizeof(CH_Address) - 1);
}

static void load_effect_set_unlocked(uint32_t effect_set) {
  CH_DBEffectSetEntry* e = &effect_set_entries[effect_set];
  void* compressed = db_read_alloc(get_db(), e->fileloc, e->compressed_size);
  uint32_t len;
  effect_set_data[effect_set] =
    decompress_all(compressed, e->compressed_size, CH_COMPRESSTYPE_DATA, &len);
  safe_free(compressed);
}

/*
 * Warning: this can be expensive. use sparingly.
 */
static CH_BunchedEffect* get_effects_for(CH_DBCodeInfoEntry* code_info) {
  pthread_mutex_lock(&effect_set_data_mutex);
  if (!effect_set_data[code_info->effect_set]) {
    load_effect_set_unlocked(code_info->effect_set);
  }
  pthread_mutex_unlock(&effect_set_data_mutex);

  return (CH_BunchedEffect*)
    (effect_set_data[code_info->effect_set] + code_info->offset_in_effect_set);
}

static int find_address_for_instruction(QueryThread* q, CH_DBCodeInfoEntry* code_info,
    uint32_t instruction_index, CH_Address* result) {
  CH_BunchedEffect* effects = get_effects_for(code_info);
  int i;
  for (i = 0; i < code_info->num_bunched_effects; ++i) {
    CH_BunchedEffect* effect = &effects[i];
    if (effect->map == CH_MAP_INSTR_EXEC &&
        effect->first_instruction_index <= instruction_index &&
        effect->last_instruction_index >= instruction_index) {
      int atom;
      CH_Address addr = (CH_Address)effect->static_offset;
      if (effect->uses_dynamic_offset) {
        debugger_error(q, "bad.instruction.map",
            "INSTR_EXEC maps should not use dynamic offsets");
        return 0;
      }
      for (atom = 0; atom < CH_EFFECT_ATOMS; ++atom) {
        uint8_t increment = effect->atoms.atoms[atom].length_increment;
        if (!increment)
          break;
        if (effect->atoms.atoms[atom].instruction_index + effect->first_instruction_index
            == instruction_index) {
          *result = addr;
          return 1;
        }
        addr += increment;
      }
    }
  }
  debugger_error(q, "bad.instruction.effects",
      "CodeInfo effects did not cover all instructions");
  return 0;
}

typedef struct {
  CH_Semaphore* completion_semaphore;
  uint32_t      effect_set;
} LoadEffectSetClosure;
static void load_effect_set_unlocked_thread(void* closure) {
  LoadEffectSetClosure* cl = closure;
  load_effect_set_unlocked(cl->effect_set);
  semaphore_remove(cl->completion_semaphore);
  safe_free(cl);
}

static void ensure_effect_sets_loaded(CH_DBRegLogChunk* data,
    uint32_t instruction_index) {
  CH_Semaphore completion_semaphore;
  uintptr_t count = (effect_set_entry_count + PTR_BITS - 1)/PTR_BITS;
  uintptr_t* effect_set_bitmap = safe_malloc(count*sizeof(uintptr_t));
  uint32_t code_max = data->num_codes_executed;
  uint8_t* instructions_retired = (uint8_t*)(data + 1);
  uint32_t* code_indexes =
    align_pointer(instructions_retired + code_max, sizeof(uint32_t));
  uint32_t i;

  memset(effect_set_bitmap, 0, count*sizeof(uintptr_t));

  for (i = 0; i < code_max; ++i) {
    uint8_t retired = instructions_retired[i];
    uint32_t code_index = code_indexes[i];
    uint32_t effect_set = code_info_entries[code_index].effect_set;

    effect_set_bitmap[effect_set/PTR_BITS] |= 1L << (effect_set & (PTR_BITS - 1));
    
    if (instruction_index < retired)
      break;
    instruction_index -= retired;
  }
  
  semaphore_init(&completion_semaphore);
  pthread_mutex_lock(&effect_set_data_mutex);
  for (i = 0; i < count; ++i) {
    int j;
    if (!effect_set_bitmap[i])
      continue;
      
    for (j = 0; j < PTR_BITS; ++j) {
      if (effect_set_bitmap[i] & (1L << j)) {
        uint32_t effect_set = i*PTR_BITS + j;
        if (!effect_set_data[effect_set]) {
          LoadEffectSetClosure closure = {&completion_semaphore, effect_set};
          LoadEffectSetClosure* cl = safe_malloc(sizeof(LoadEffectSetClosure));
          *cl = closure;
          semaphore_add(&completion_semaphore);
          run_on_thread(load_effect_set_unlocked_thread, cl);
        }
      }
    }
  }
  safe_free(effect_set_bitmap);
  semaphore_wait_for_all_removed(&completion_semaphore);
  pthread_mutex_unlock(&effect_set_data_mutex);
  semaphore_destroy(&completion_semaphore);
}

/* this stuff is all little-endian only! It also does unaligned accesses. */

static void* get_reg_addr(CH_Context* ctx, uint8_t reg) {
  return (uint8_t*)ctx + reg_addr_offset_table[reg];
}

static void add_128bit(void* dest, int8_t delta, void* src) {
  uint64_t* d = dest;
  uint64_t* s = src;
  uint64_t low = s[0] + delta;
  if ((low ^ s[0]) & ((uint64_t)1 << 63)) {
    d[1] = s[1] + (delta > 0) ? 1 : -1;
  }
  d[0] = low;
}

#define REG_EFFECT_WITH_SIZE(effect, bytes_pow2, code) \
    case (effect << 3)|bytes_pow2: { int size = 1<<bytes_pow2; code; break; }
/* up to 128-bit operations ((1 << 4) bytes) are supported */
#define REG_EFFECT(effect, code) \
    REG_EFFECT_WITH_SIZE(effect, 0, code) \
    REG_EFFECT_WITH_SIZE(effect, 1, code) \
    REG_EFFECT_WITH_SIZE(effect, 2, code) \
    REG_EFFECT_WITH_SIZE(effect, 3, code) \
    REG_EFFECT_WITH_SIZE(effect, 4, code)

#define REG_EFFECT_WITH_SIZE_T(effect, bytes_pow2, t, code) \
    case (effect << 3)|bytes_pow2: { typedef t TYPE; code; break; }
#define REG_EFFECT_T(effect, code) \
    REG_EFFECT_WITH_SIZE_T(effect, 0, int8_t, code) \
    REG_EFFECT_WITH_SIZE_T(effect, 1, int16_t, code) \
    REG_EFFECT_WITH_SIZE_T(effect, 2, int32_t, code) \
    REG_EFFECT_WITH_SIZE_T(effect, 3, int64_t, code)

#define REG_EFFECT_WITH_NO_SIZE(effect, bytes_pow2) \
    case (effect << 3)|bytes_pow2:
/* up to 128-bit operations ((1 << 4) bytes) are supported */
#define REG_EFFECT_NO_SIZE(effect, code) \
    REG_EFFECT_WITH_NO_SIZE(effect, 0) \
    REG_EFFECT_WITH_NO_SIZE(effect, 1) \
    REG_EFFECT_WITH_NO_SIZE(effect, 2) \
    REG_EFFECT_WITH_NO_SIZE(effect, 3) \
    REG_EFFECT_WITH_NO_SIZE(effect, 4) { code; break; }

typedef struct {
  uint8_t* buffer;
  uint8_t* allocation_blocks[CH_PTR_LOG2_BYTES];
  uint8_t  saved_dynreg;
} RegLogBuffer;

static void init_reg_log_buffer(uint8_t* ptr, RegLogBuffer* buf) {
  buf->buffer = ptr;
  memset(buf->allocation_blocks, 0, sizeof(buf->allocation_blocks));
  buf->saved_dynreg = 0;
}

static uint8_t* lookup_log(RegLogBuffer* buf, int log2_bytes) {
  uint8_t* r;
  
  if (log2_bytes >= CH_PTR_LOG2_BYTES) {
    r = buf->buffer;
    buf->buffer += 1 << log2_bytes;
    return r;
  }
  
  if (buf->allocation_blocks[log2_bytes]) {
    r = buf->allocation_blocks[log2_bytes];
    buf->allocation_blocks[log2_bytes] = NULL;
    return r;
  }
  
  r = lookup_log(buf, log2_bytes + 1);
  buf->allocation_blocks[log2_bytes] = r + (1 << log2_bytes);
  return r;
}

static int apply_reg_effect(QueryThread* q, CH_RegEffect* e, CH_Context* ctx,
                            RegLogBuffer* buf) {
  int16_t imm = (e->imm1 << 8)|e->imm0;
  void* reg_addr = get_reg_addr(ctx, e->reg);
  switch ((e->type << 3) | e->bytes_pow2) {
    REG_EFFECT_NO_SIZE(CH_EFFECT_REG_READ, {;})
    REG_EFFECT_NO_SIZE(CH_EFFECT_DYNREG_READ, {
      buf->saved_dynreg = *lookup_log(buf, 0);
    })
    REG_EFFECT(CH_EFFECT_REG_WRITE, {
      memcpy(reg_addr, lookup_log(buf, e->bytes_pow2), size);
    })
    REG_EFFECT(CH_EFFECT_DYNREG_WRITE, {
      uint8_t reg = *lookup_log(buf, 0);
      buf->saved_dynreg = reg;
      memcpy(get_reg_addr(ctx, reg), lookup_log(buf, e->bytes_pow2), size);
    })
    REG_EFFECT_T(CH_EFFECT_REG_SETCONST, {*(TYPE*)reg_addr = imm;})
    REG_EFFECT_T(CH_EFFECT_REG_ADDCONST, {*(TYPE*)reg_addr += imm;})
    REG_EFFECT_T(CH_EFFECT_REG_ADDREG,
                 {*(TYPE*)reg_addr = (int8_t)e->imm0 + *(TYPE*)get_reg_addr(ctx, e->imm1);})
    case ((CH_EFFECT_REG_ADDREG << 3) | 4):
      add_128bit(reg_addr, (int8_t)e->imm0, get_reg_addr(ctx, e->imm1));
      break;
    default:
      debugger_error(q, "bad.reg.effect.type",
          "Register effect type %d (size %d) not understood", e->type, 1 << e->bytes_pow2);
      return 0;
  }
  return 1;
}

typedef struct {
  uint32_t code_index;
  uint32_t last_log_offset;
  uint16_t bunched_effect_log_size;
  uint16_t reg_effect_log_size;
} CodeExecEntry;

static uint32_t hash_code_index(uint32_t v, uint32_t size) {
  return (v+1)%size;
}

static uint16_t compute_bunched_effect_dynamic_offsets_log_size(CH_BunchedEffect* e, int count) {
  int i;
  uint32_t v = 0;
  for (i = 0; i < count; ++i) {
    v += e[i].has_dynamic_offset*sizeof(CH_Address);
  }
  return (uint16_t)align_size_to_pointer(v);
}

static uint16_t compute_reg_effect_log_size(CH_RegEffect* e, int count) {
  int i;
  uint32_t v = 0;
  for (i = 0; i < count; ++i) {
    uint32_t size = 1 << e[i].bytes_pow2;
    switch (e[i].type) {
      case CH_EFFECT_DYNREG_READ: v += 1; break;
      case CH_EFFECT_REG_WRITE: v += size; break;
      case CH_EFFECT_DYNREG_WRITE: v += 1 + size; break;
      default: break;
    }
  }
  return (uint16_t)align_size_to_pointer(v);
}

static void add_data_record(void* dest, void* src, uint32_t size_bytes) {
  uintptr_t* d = dest;
  uintptr_t* s = src;
  int i;
  for (i = 0; i < size_bytes; i += sizeof(void*)) {
    *d += *s;
    d++;
    s++;
  }
}

typedef int (* WriteCheckCallback)(void* closure, uint32_t tstamp_offset,
    uint8_t reg, uint8_t bytes, void* value);
    
static int check_reg_effect(CH_RegEffect* e, CH_Context* ctx, uint8_t saved_dynreg,
    uint32_t tstamp_offset,
    uint64_t write_check_mask, WriteCheckCallback write_check_callback,
    void* write_check_callback_closure) {
  int reg;
  switch (e->type) {
    case CH_EFFECT_REG_WRITE:
    case CH_EFFECT_REG_ADDCONST:
    case CH_EFFECT_REG_ADDREG:
    case CH_EFFECT_REG_SETCONST:
      reg = e->reg;
      break;
    case CH_EFFECT_DYNREG_WRITE:
      reg = saved_dynreg;
      break;
    default:
      return 1;
  }
  if (!(write_check_mask & (1L << reg)))
    return 1;
  return write_check_callback(write_check_callback_closure, tstamp_offset, reg,
                              1 << e->bytes_pow2, get_reg_addr(ctx, reg));
}

static void reconstruct_registers(QueryThread* q, CH_DBRegLogEntry* e,
    CH_DBRegLogChunk* data, uint32_t tstamp_offset, uint8_t* reg_bytes_requested,
    CH_RegReaderResultCallback callback, void* callback_closure,
    uint64_t write_check_mask, WriteCheckCallback write_check_callback,
    void* write_check_callback_closure) {
  CH_Context registers = data->initial_context;
  uint32_t code_max = data->num_codes_executed;
  uint8_t* instructions_retired = (uint8_t*)(data + 1);
  uint32_t instruction_index = tstamp_offset;
  uint32_t* code_indexes =
    align_pointer(instructions_retired + code_max, sizeof(uint32_t));
  uint32_t i;
  uint8_t* log_data = align_pointer(code_indexes + code_max, sizeof(uintptr_t));
  CH_GrowBuf log_entry_buf;
  uint32_t log_data_table_count = 0;
  uint32_t code_exec_table_size = code_max*2;
  /* The log data for each code-index execution is stored as the difference
   * between the true log data and the true log data for the previous execution
   * of this code-index in this RegLogChunk (or zero if there was no such
   * previous execution. Therefore we need a hash table indexed by code-indexes
   * to record whether there was a previous execution and what its log data
   * was. */
  CodeExecEntry* code_exec_table = safe_malloc(sizeof(CodeExecEntry)*code_exec_table_size);
  int dynamic_offsets_in_reg_log = get_db()->header.dynamic_offsets_in_reg_log;
  uint32_t instruction_count = 0;
  
  init_buf(&log_entry_buf);
  memset(code_exec_table, 0, sizeof(CodeExecEntry)*code_exec_table_size);

  for (i = 0; i < code_max; ++i) {
    uint32_t code_index = code_indexes[i];
    CH_DBCodeInfoEntry* code_info = &code_info_entries[code_index];
    uint8_t retired = instructions_retired[i];
    CH_BunchedEffect* effects = (CH_BunchedEffect*)
      (effect_set_data[code_info->effect_set] + code_info->offset_in_effect_set);
    CH_RegEffect* reg_effects = (CH_RegEffect*)
      (effects + code_info->num_bunched_effects);
    uint32_t j;
    uint32_t hash = code_index;
    CodeExecEntry* exec_entry;
    RegLogBuffer reg_log_buf;
    
    for (;;) {
      hash = hash_code_index(hash, code_exec_table_size);
      exec_entry = &code_exec_table[hash];
      if (exec_entry->code_index == code_index)
        break;
      if (exec_entry->code_index == 0) {
        uint16_t bunched_effect_log_size = !dynamic_offsets_in_reg_log ? 0 :
          compute_bunched_effect_dynamic_offsets_log_size(effects, code_info->num_bunched_effects);
        uint16_t reg_effect_log_size =
          compute_reg_effect_log_size(reg_effects, code_info->num_reg_effects);
        exec_entry->code_index = code_index;
        exec_entry->last_log_offset = log_data_table_count;
        exec_entry->bunched_effect_log_size = bunched_effect_log_size;
        exec_entry->reg_effect_log_size = reg_effect_log_size;
        log_data_table_count += reg_effect_log_size;
        ensure_buffer_size(&log_entry_buf, log_data_table_count);
        memset(log_entry_buf.data + exec_entry->last_log_offset, 0, reg_effect_log_size);
        break;
      }
    }

    log_data += exec_entry->bunched_effect_log_size;
    /* compute the true log data record by *adding* the log data to the previous
       log data record in pointer-sized blocks */
    add_data_record(log_entry_buf.data + exec_entry->last_log_offset,
                    log_data, exec_entry->reg_effect_log_size);
    log_data += exec_entry->reg_effect_log_size;

    init_reg_log_buffer(log_entry_buf.data + exec_entry->last_log_offset,
                        &reg_log_buf);
    for (j = 0; j < code_info->num_reg_effects; ++j) {
      if (reg_effects[j].instruction_index < instruction_index) {
        if (!apply_reg_effect(q, &reg_effects[j], &registers, &reg_log_buf)) {
          safe_free(log_entry_buf.data);
          safe_free(code_exec_table);
          return;
        }
        if (write_check_callback) {
          if (!check_reg_effect(&reg_effects[j], &registers, reg_log_buf.saved_dynreg,
                                instruction_count + reg_effects[j].instruction_index,
                                write_check_mask, write_check_callback,
                                write_check_callback_closure)) {
            safe_free(log_entry_buf.data);
            safe_free(code_exec_table);
            return;
          }
        }
      }
    }
    
    if (instruction_index < retired)
      break;
    instruction_index -= retired;
    instruction_count += retired;
  }

  if (callback) {
    for (i = 0; i < CH_NUM_REGS; ++i) {
      if (reg_bytes_requested[i]) {
        if (!callback(callback_closure, q, i, reg_size_table[i],
                      get_reg_addr(&registers, i)))
          break;
      }
    }
  }

  safe_free(log_entry_buf.data);
  safe_free(code_exec_table);
}

void reg_read(QueryThread* q, CH_TStamp tstamp, uint8_t* reg_bytes_requested,
              CH_RegReaderResultCallback callback, void* callback_closure) {
  CH_DBRegLogEntry* e = find_reg_log_entry_containing(tstamp);
  uint32_t len;
  CH_DBRegLogChunk* data;
  uint32_t i;
  uint32_t num_regs_to_lookup;
  uint32_t instruction_index;
  
  if (!e || (tstamp - e->first_tstamp) > UINT32_MAX) {
    debugger_error(q, "bad.reg.tstamp",
        "TStamp '%lld' has no associated register data", (long long)tstamp);
    return;
  }
  instruction_index = (uint32_t)(tstamp - e->first_tstamp);
  
  if (reg_bytes_requested[CH_REG_THREAD]) {
    if (!callback(callback_closure, q, CH_REG_THREAD, sizeof(uint32_t),
                  &e->pthread_cookie))
      return;
  }
  
  data = decompression_cache_acquire(e->reg_log_chunk_fileloc,
                                     e->reg_log_chunk_compressed_size,
                                     CH_COMPRESSTYPE_DATA, &len);

  if (reg_bytes_requested[CH_REG_PC]) {
    uint32_t code_max = data->num_codes_executed;
    uint8_t* instructions_retired = (uint8_t*)(data + 1);
    uint32_t* code_indexes =
      align_pointer(instructions_retired + code_max, sizeof(uint32_t));
    CH_DBCodeInfoEntry* code_info;
    CH_Address addr;

    for (i = 0; i < code_max; ++i) {
      uint8_t retired = instructions_retired[i];
      if (instruction_index < retired)
        break;
      instruction_index -= retired;
    }
    if (i >= code_max) {
      debugger_error(q, "bad.reg.tstamp",
          "TStamp '%lld' has no associated register data", (long long)tstamp);
      decompression_cache_release(e->reg_log_chunk_fileloc, data);
      return;
    }
    code_info = &code_info_entries[code_indexes[i]];
  
    if (!find_address_for_instruction(q, code_info, instruction_index, &addr) ||
        !callback(callback_closure, q, CH_REG_PC, sizeof(CH_Address), &addr)) {
      decompression_cache_release(e->reg_log_chunk_fileloc, data);
      return;
    }
  }
  instruction_index = (uint32_t)(tstamp - e->first_tstamp);
  
  /* don't bother with the hard stuff if the caller only wanted thread and/or pc */
  num_regs_to_lookup = 0;
  for (i = 0; i < CH_NUM_REGS; ++i) {
    if (reg_bytes_requested[i]) {
      ++num_regs_to_lookup;
    }
  }
  if (num_regs_to_lookup) {
    /* first, ensure that all relevant effect sets are loaded */
    ensure_effect_sets_loaded(data, instruction_index);
    /* now perform register reconstruction */
    reconstruct_registers(q, e, data, instruction_index,
                          reg_bytes_requested, callback, callback_closure,
                          0, NULL, NULL);
  }
  
  decompression_cache_release(e->reg_log_chunk_fileloc, data);
}

static void try_complete_semaphore(CH_Semaphore* completion_semaphore) {
  if (completion_semaphore) {
    semaphore_remove(completion_semaphore);
  }
}

typedef struct {
  uint32_t tstamp_offset;
  uint8_t  reg;
} RegWriteRecord;
typedef struct {
  CH_GrowBuf reg_write_buf;
  int        reg_write_count;
} WriteCheckerClosure;

static int reg_write_accumulator(void* closure, uint32_t tstamp_offset,
                                 uint8_t reg, uint8_t bytes, void* value)
{
  WriteCheckerClosure* cl = closure;
  RegWriteRecord* r;
  
  ensure_buffer_size(&cl->reg_write_buf, (cl->reg_write_count + 1)*sizeof(RegWriteRecord));
  r = (RegWriteRecord*)cl->reg_write_buf.data + cl->reg_write_count;
  r->reg = reg;
  r->tstamp_offset = tstamp_offset;
  ++cl->reg_write_count;
  /* keep going; we need to see all writes */
  return 1;
}

void reg_scan_for_write(QueryThread* q, CH_TStamp tstamp,
                        uint32_t pthread_cookie, int direction,
                        uint8_t* reg_bytes_requested,
                        CH_RegWriteScanResultCallback callback,
                        void* callback_closure,
                        CH_Semaphore* completion_semaphore) {
  CH_DBRegLogEntry* e = find_reg_log_entry_containing(tstamp);
  uint64_t mask = 0;
  int i;

  for (i = 0; i < CH_REG_MAX; ++i) {
    if (reg_bytes_requested[i]) {
      mask |= 1L << i;
    }
  }

  if (e == NULL || !mask) {
    try_complete_semaphore(completion_semaphore);
    return;
  }

  while (e && e >= reg_log_entries) {
    if (((e->registers_maybe_modified & mask) || reg_bytes_requested[CH_REG_PC] ||
         reg_bytes_requested[CH_REG_THREAD]) &&
        (tstamp - e->first_tstamp) <= UINT32_MAX &&
        e->pthread_cookie == pthread_cookie) {
      uint32_t len;
      CH_DBRegLogChunk* data = decompression_cache_acquire(e->reg_log_chunk_fileloc,
                                                           e->reg_log_chunk_compressed_size,
                                                           CH_COMPRESSTYPE_DATA, &len);
      uint32_t instruction_index = (uint32_t)(tstamp - e->first_tstamp);
      WriteCheckerClosure closure;
      int i;
      
      init_buf(&closure.reg_write_buf);
      closure.reg_write_count = 0;
      
      ensure_effect_sets_loaded(data, instruction_index);
      reconstruct_registers(q, e, data, instruction_index, NULL, NULL, NULL,
                            mask, reg_write_accumulator, &closure);

      /* now 'closure' contains a list of the pertinent register writes, in increasing
         time order */
      --instruction_index;
      for (i = closure.reg_write_count - 1; i >= -1; --i) {
        RegWriteRecord* r = (RegWriteRecord*)closure.reg_write_buf.data + i;
        
        while (reg_bytes_requested[CH_REG_PC] &&
               (i == -1 || instruction_index > r->tstamp_offset)) {
          if (!callback(callback_closure, q,
                        e->first_tstamp + instruction_index, CH_REG_PC)) {
            try_complete_semaphore(completion_semaphore);
            safe_free(closure.reg_write_buf.data);
            decompression_cache_release(e->reg_log_chunk_fileloc, data);
            return;
          }
          if (instruction_index == 0)
            break;
          --instruction_index;
        }
        
        if (i < 0)
          break;
        if (!callback(callback_closure, q,
                      e->first_tstamp + r->tstamp_offset, r->reg)) {
          try_complete_semaphore(completion_semaphore);
          safe_free(closure.reg_write_buf.data);
          decompression_cache_release(e->reg_log_chunk_fileloc, data);
          return;
        }
      }
      
      safe_free(closure.reg_write_buf.data);
      decompression_cache_release(e->reg_log_chunk_fileloc, data);

      if (reg_bytes_requested[CH_REG_THREAD]) {
        if (!callback(callback_closure, q,  e->first_tstamp, CH_REG_THREAD)) {
          try_complete_semaphore(completion_semaphore);
          return;
        }          
      }      
    }
      
    --e;
  }
  
  try_complete_semaphore(completion_semaphore);
}

typedef struct {
  CH_Address limit;
  uint32_t   begin_tstamp_offset;
  uint32_t   tstamp_offset;
  uint8_t    found;
} SPCheckClosure;

static int reg_write_SP_check(void* closure, uint32_t tstamp_offset,
                              uint8_t reg, uint8_t bytes, void* value) {
  SPCheckClosure* cl = closure;
  if (tstamp_offset < cl->begin_tstamp_offset ||
      *(uintptr_t*)value <= cl->limit)
    return 1;
    
  cl->tstamp_offset = tstamp_offset;
  cl->found = 1;
  return 0;
}

CH_TStamp reg_scan_for_SP_greater_than(QueryThread* q, CH_TStamp begin_tstamp,
                                       CH_TStamp end_tstamp,
                                       uint32_t pthread_cookie, CH_Address limit) {
  CH_DBRegLogEntry* e = find_reg_log_entry_containing(begin_tstamp);
  if (!e) {
    debugger_error(q, "bad.reg.tstamp",
        "TStamp '%lld' has no associated register data", (long long)begin_tstamp);
    return 0;
  }
  
  while (e < reg_log_entries + reg_log_entry_count &&
         e->first_tstamp < end_tstamp) {
    uint64_t begin_tstamp_offset =
      e->first_tstamp < begin_tstamp ? begin_tstamp - e->first_tstamp : 0;
    if (begin_tstamp_offset != (uint32_t)begin_tstamp_offset) {
      debugger_error(q, "bad.reg.tstamp",
          "TStamp '%lld' has no associated register data (weird overflow)",
          (long long)begin_tstamp);
      return 0;
    }
    if (e->SP_max > limit && e->pthread_cookie == pthread_cookie) {
      uint32_t instruction_index;
      uint32_t len;
      CH_DBRegLogChunk* data =
        decompression_cache_acquire(e->reg_log_chunk_fileloc,
                                    e->reg_log_chunk_compressed_size,
                                    CH_COMPRESSTYPE_DATA, &len);
      uint64_t mask = 1 << CH_X86_SP;
      SPCheckClosure closure = { limit, (uint32_t)begin_tstamp_offset, 0, 0 };

      if (end_tstamp - e->first_tstamp > (uint32_t)-1) {
        instruction_index = (uint32_t)-1;
      } else {
        instruction_index = (uint32_t)(end_tstamp - e->first_tstamp);
      }

      ensure_effect_sets_loaded(data, instruction_index);
      reconstruct_registers(q, e, data, instruction_index, NULL, NULL, NULL,
                            mask, reg_write_SP_check, &closure);
      
      decompression_cache_release(e->reg_log_chunk_fileloc, data);
      
      if (closure.found)
        return closure.tstamp_offset + e->first_tstamp;
    }
    ++e;
  }
  
  return end_tstamp;
}
