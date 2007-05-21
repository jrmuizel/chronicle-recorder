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

#include "config.h"
#include "log_stream.h"
#include "util.h"
#include "effect_map_write.h"
#include "database_write.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

/* Trace buffers should fit in L2 cache, I guess.
   Let's have two buffers of 128K each, for now. */
static const int trace_buf_len = (128*(1<<10));
static const int trace_buf_count = 2;
static const int control_in_fd = 0;
static const int control_out_fd = 1;

static int read_trace_from_input = 0;
static FILE* pretty_print_out = 0;
static int build_index = 1;
static char* save_file = 0;
static char* db_file = 0;

static uint32_t trace_control_flags;
static int save_fd = -1;
static int db_fd = -1;
static uint64_t save_offset;
static uint64_t pretty_print_offset = 0;

typedef void (* RecordHandler)(CH_RecordHeader* record, void* closure);

static CH_TStamp global_tstamp = 1;
static CH_EffectMap builtin_maps[CH_MAX_BUILTIN_MAP+1];
static char const* builtin_map_names[CH_MAX_BUILTIN_MAP+1] = {
  "MAP_INSTR_EXEC", "MAP_MEM_READ", "MAP_MEM_WRITE", "MAP_ENTER_SP"
};

static CH_DBFile db;

static CH_GrowBuf address_map_buffer;
static uintptr_t address_map_buffer_count;

static CH_DBRegLogChunk reg_log_chunk_header;
static CH_TStamp reg_log_chunk_tstamp;
static uint32_t reg_log_pthread_cookie;
static CH_GrowBuf reg_log_instructions_retired;
static CH_GrowBuf reg_log_code_indexes;
static uintptr_t reg_log_code_index_count;
static CH_GrowBuf reg_log_chunk;
static uintptr_t reg_log_chunk_used;
static uint64_t registers_maybe_modified;

static CH_GrowBuf reg_log_entry;
static uintptr_t reg_log_entry_count;
static CH_Semaphore reg_log_entry_semaphore;
static pthread_mutex_t reg_log_entry_mutex;

static uint8_t* effect_set;
static uint32_t effect_set_used;

static CH_GrowBuf effect_set_entries;
static uintptr_t effect_set_entry_count;
static CH_Semaphore effect_set_entry_semaphore;
static pthread_mutex_t effect_set_entry_mutex;

static CH_GrowBuf code_info_entries;
static uintptr_t code_info_entries_count;

static void* zeroes; // 64K of zeroes

static CH_BunchedEffectAtoms zero_atoms;

typedef struct _CodeClosure {
  uint16_t num_instructions;
  uint16_t num_bunched_effects;
  /* the total number of dynamic offsets used by all bunches */
  uint16_t bunched_offsets_count;
  /* the size of the register log if the block is complete; multiple of
     pointer size */
  uint16_t reg_log_size;
  
  uint64_t registers_maybe_modified;
  
  uintptr_t last_chunk_entry_visited;
} CodeClosure;
/* aligned-to-pointer CH_BunchedEffects follow */
/* copy of the last-executed bunched-effect offsets follows */
/* copy of the last-executed reg-log buffer follows */

typedef struct {
  RecordHandler handler;
  void* closure;
} RecordHandlerClosure;
static RecordHandlerClosure* record_handlers;
static uint32_t record_handler_size;

static uint32_t align_size_to_pointer(uint32_t len) {
  return (len + sizeof(void*) - 1)&~(sizeof(void*) - 1);
}

static void* align_to_pointer(void* len) {
  return (void*)(((uintptr_t)len + sizeof(void*) - 1)&~(sizeof(void*) - 1));
}

static void set_record_handler(uint32_t type, RecordHandler handler,
                               void* closure) {
  if (type >= record_handler_size) {
    uint32_t new_size = record_handler_size*2 + 10;
    uint32_t i;
    if (type >= new_size) {
      new_size = type + 1;
    }
    RecordHandlerClosure* new_handlers =
      (RecordHandlerClosure*)safe_malloc(new_size*sizeof(RecordHandlerClosure));
    memcpy(new_handlers, record_handlers,
           record_handler_size*sizeof(RecordHandlerClosure));
    safe_free(record_handlers);
    
    for (i = record_handler_size; i < new_size; ++i) {
      new_handlers[i].handler = NULL;
      new_handlers[i].closure = NULL;
    }
    
    record_handlers = new_handlers;
    record_handler_size = new_size;
  }

  safe_free(record_handlers[type].closure);
  record_handlers[type].handler = handler;
  record_handlers[type].closure = closure;
}

static CH_RegType get_register_type(uint8_t reg)
{
#ifdef CH_X86
  if (reg < CH_X86_GP_REGS + CH_X86_GP_REGS_COUNT)
    return CH_REGTYPE_GP;
  if (reg >= CH_X86_SSE_REGS &&
      reg < CH_X86_SSE_REGS + CH_X86_SSE_REGS_COUNT)
    return CH_REGTYPE_X86_SSE;
  if (reg >= CH_X86_FP_REGS &&
      reg < CH_X86_FP_REGS + CH_X86_FP_REGS_COUNT)
    return CH_REGTYPE_X86_FP;
  if (reg == CH_X86_FPTOP_REG)
    return CH_REGTYPE_X86_FPTOP;
  return CH_REGTYPE_UNKNOWN;
#else
#error Unknown architecture
#endif
}

static void parse_options(int argc, char** argv) {
  argv++, argc--;
  save_file = getenv("CHRONICLE_SAVE");
  db_file = getenv("CHRONICLE_DB");

  while (argc > 0) {
    if (strcmp(argv[0], "--input") == 0) {
      read_trace_from_input = 1;
    } else if (strcmp(argv[0], "--print") == 0) {
      pretty_print_out = stdout;
    } else if (strcmp(argv[0], "--noindex") == 0) {
      build_index = 0;
    } else {
      fatal_error(2, "Invalid option: %s", argv[0]);
    }
    argv++, argc--;
  }

  if (pretty_print_out == stdout && !read_trace_from_input)
    fatal_error(2, "Can't print trace in slave mode");
  if (read_trace_from_input && save_file) 
    fatal_error(2, "Can't save a trace we gather from input!");
}

static void write_control(const void* data, int len) {
  while (len > 0) {
    int written = write(control_out_fd, data, len);
    if (written <= 0) {
      if (errno == EPIPE) {
        /* the tracer must have exited. Just discard this message. */
        return;
      }
      fatal_perror(1, "Cannot send to pipe");
    }
    len -= written;
    data = (char*)data + written;
  }
}

static int read_control(void* data, int len) {
  while (len > 0) {
    int r = read(control_in_fd, data, len);
    if (r < 0)
      fatal_perror(1, "Cannot read from pipe");
    if (r == 0) {
      /* the tracer must have exited */
      return 0;
    }
    len -= r;
    data = (char*)data + r;
  }
  return 1;
}

static char tmp_name[] = "/tmp/chronicleXXXXXX";

static void unlink_tmp() {
  unlink(tmp_name);
}

static void sort_atoms_by_instruction(CH_BunchedEffectAtom* atoms) {
  int i, j;
  /* Bubble sort since we have only a small number of elements.
     Also, effects are usually already in instruction order so we
     want to exit as quickly as possible if the list is already
     sorted. */
  for (i = 0; i < CH_EFFECT_ATOMS - 1; ++i) {
    int sorted = 1;
    for (j = i + 1; j < CH_EFFECT_ATOMS; ++j) {
      if (atoms[j].length_increment == 0)
        break;
      if (atoms[i].instruction_index > atoms[j].instruction_index) {
        sorted = 0;
        CH_BunchedEffectAtom tmp = atoms[j];
        atoms[j] = atoms[i];
        atoms[i] = tmp;
      }
    }
    if (sorted)
      return;
  }
}

static void exec_slow_path(CH_Record_Exec* r, CodeClosure* cl) {
  uintptr_t* chunk_data;
  uint8_t instructions_retired = r->instructions_retired;
  int i, j;
  CH_BunchedEffect* bunch = (CH_BunchedEffect*)(cl + 1);
  uintptr_t* dynamic_offsets = align_to_pointer(r + 1);
  uintptr_t* bunch_data = dynamic_offsets + cl->bunched_offsets_count;
  uintptr_t dynamic_offsets_by_map[4] = { 0,0,0,0 };
  uintptr_t new_chunk_size = reg_log_chunk_used +
    (CH_SAVE_INSTRUCTION_DYNAMIC_OFFSETS ?
     cl->bunched_offsets_count*sizeof(uintptr_t) : 0) +
    cl->reg_log_size;
  uintptr_t new_code_index_count = reg_log_code_index_count + 1;
  uint16_t bunch_count = cl->num_bunched_effects;
  uintptr_t* saved_offsets_and_reglog = (uintptr_t*)(bunch + bunch_count);
  uintptr_t* previous_execution_data = 
    cl->last_chunk_entry_visited == reg_log_entry_count
    ? saved_offsets_and_reglog : zeroes;
  uint16_t reg_log_size = cl->reg_log_size;

  chunk_data = (uintptr_t*)(reg_log_chunk.data + reg_log_chunk_used);
  reg_log_code_index_count = new_code_index_count;
  reg_log_chunk_used = new_chunk_size;

  /* Handle bunched effects */
  for (i = bunch_count; i > 0; --i) {
    uintptr_t static_offset = bunch->static_offset;
    uint8_t map_index = bunch->map;
    CH_EffectMap* map = &builtin_maps[map_index];
    uintptr_t dynamic_offset = dynamic_offsets_by_map[map_index];

    if (bunch->has_dynamic_offset) {
      if (bunch->first_instruction_index < instructions_retired) {
        dynamic_offset = *dynamic_offsets;
        dynamic_offsets++;
      } else {
        dynamic_offset = 0;
      }
      if (CH_SAVE_INSTRUCTION_DYNAMIC_OFFSETS) {
        *chunk_data = dynamic_offset - *previous_execution_data;
        chunk_data++, previous_execution_data++;
        *saved_offsets_and_reglog = dynamic_offset;
        saved_offsets_and_reglog++;
      }
      dynamic_offsets_by_map[map_index] = dynamic_offset;
    }
    
    if (bunch->first_instruction_index < instructions_retired) {
      uintptr_t addr =
        static_offset + (bunch->uses_dynamic_offset ? dynamic_offset : 0);

      if (bunch->last_instruction_index < instructions_retired) {
        /* all instructions retired so we can treat this more or less
           as normal */
        CH_TStamp tstamp = global_tstamp + bunch->first_instruction_index;
        if (!bunch->has_data) {
          effect_map_append(map, tstamp, addr, bunch->length, bunch->atoms);
        } else {
          effect_map_append_isodata(map, tstamp, addr, bunch->length,
                               bunch->atoms, bunch_data);
        }
      } else {
        /* Some of the instructions in the bunch did not retire.  We
           unbundle the effects and write out each effect
           independently, because we need to select only those effects
           that actually happened. We need to write out the effects in
           timestamp order, so this is a bit tricky. */
        int next_atom = 0;
        CH_BunchedEffectAtoms sorted_atoms = bunch->atoms;

        sort_atoms_by_instruction(sorted_atoms.atoms);

        while (next_atom < CH_EFFECT_ATOMS
               && sorted_atoms.atoms[next_atom].length_increment > 0) {
          uint32_t addr_delta = 0;
          for (j = 0; j < CH_EFFECT_ATOMS; ++j) {
            CH_BunchedEffectAtom atom = bunch->atoms.atoms[j];
            uint8_t instr_delta =
              bunch->first_instruction_index + atom.instruction_index;
          
            if (atom.length_increment == 0)
              break;

            if (atom.instruction_index == sorted_atoms.atoms[next_atom].instruction_index) {
              if (instr_delta < instructions_retired) {
                uintptr_t atom_addr = addr + addr_delta;
                CH_TStamp tstamp = global_tstamp + instr_delta;
            
                if (!bunch->has_data) {
                  effect_map_append(map, tstamp, atom_addr, atom.length_increment,
                               zero_atoms);
                } else {
                  effect_map_append_isodata(map, tstamp, atom_addr,
                                       atom.length_increment, zero_atoms,
                                       (uint8_t*)bunch_data + addr_delta);
                }
              }

              ++next_atom;
              if (next_atom >= CH_EFFECT_ATOMS ||
                  sorted_atoms.atoms[next_atom].length_increment == 0)
                break;
            }

            addr_delta += atom.length_increment;
          }
        }
      }
    }

    if (bunch->has_data) {
      bunch_data = align_to_pointer((uint8_t*)bunch_data + bunch->length);
    }

    ++bunch;
  }

  /* store reg-log delta */
  for (i = 0; i < reg_log_size; i += sizeof(uintptr_t)) {
    uintptr_t log_word = *bunch_data;
    *chunk_data = log_word - *previous_execution_data;
    *saved_offsets_and_reglog = log_word;
    chunk_data++, bunch_data++, previous_execution_data++;
    saved_offsets_and_reglog++;
  }

  cl->last_chunk_entry_visited = reg_log_entry_count;

  global_tstamp += instructions_retired;
}

/* really, the heart of this whole thing. Gets executed for every
   block! */
static void exec_handler(CH_RecordHeader* header, void* closure) {
  CH_Record_Exec* r = (CH_Record_Exec*)header;
  CodeClosure* cl = closure;
  CH_BunchedEffect* bunch = (CH_BunchedEffect*)(cl + 1);
  uintptr_t* dynamic_offsets = align_to_pointer(r + 1);
  int i;
  uint16_t bunched_offsets_count = cl->bunched_offsets_count;
  uintptr_t* bunch_data = dynamic_offsets + bunched_offsets_count;
  uint16_t reg_log_size = cl->reg_log_size;
  uintptr_t new_chunk_size = reg_log_chunk_used +
    (CH_SAVE_INSTRUCTION_DYNAMIC_OFFSETS ?
     bunched_offsets_count*sizeof(uintptr_t) : 0) +
    reg_log_size;
  uintptr_t index = reg_log_code_index_count;
  uintptr_t new_code_index_count = index + 1;
  uintptr_t* chunk_data;
  uintptr_t dynamic_offsets_by_map[4] = { 0,0,0,0 };
  uint16_t bunch_count = cl->num_bunched_effects;
  uintptr_t* saved_offsets_and_reglog = (uintptr_t*)(bunch + bunch_count);
  uintptr_t* previous_execution_data = 
    cl->last_chunk_entry_visited == reg_log_entry_count
    ? saved_offsets_and_reglog : zeroes;

  ensure_buffer_size(&reg_log_instructions_retired,
                     new_code_index_count);
  ensure_buffer_size(&reg_log_code_indexes,
                     new_code_index_count*sizeof(uint32_t));
  ensure_buffer_size(&reg_log_chunk, new_chunk_size + sizeof(uintptr_t));

  reg_log_instructions_retired.data[index] = r->instructions_retired;
  ((uint32_t*)reg_log_code_indexes.data)[index] = r->header.code_index;

  /* update the register modification bits even if some of the register effects
     for the code block didn't happen. That's OK because it's only a
     *maybe* hint. If we needed to compute precise register effects we'd have
     to do a lot more work, including keeping around the register effect data
     for many blocks. */
  registers_maybe_modified |= cl->registers_maybe_modified;

  if (r->instructions_retired != cl->num_instructions) {
    /* Carefully figure out which effects actually occurred. */
    exec_slow_path(r, cl);
    return;
  }

  chunk_data = (uintptr_t*)(reg_log_chunk.data + reg_log_chunk_used);
  reg_log_code_index_count = new_code_index_count;
  reg_log_chunk_used = new_chunk_size;
  
  /* handle bunched effects */
  /* trying to avoid unpredictable conditional branches */
  for (i = bunch_count; i > 0; --i) {
    uintptr_t static_offset = bunch->static_offset;
    uintptr_t addr;
    uint8_t map_index = bunch->map;
    CH_EffectMap* map = &builtin_maps[map_index];
    uintptr_t dynamic_offset = dynamic_offsets_by_map[map_index];
    CH_TStamp tstamp = global_tstamp + bunch->first_instruction_index;

    if (bunch->has_dynamic_offset) {
      dynamic_offset = *dynamic_offsets;
      dynamic_offsets++;
      if (CH_SAVE_INSTRUCTION_DYNAMIC_OFFSETS) {
        *chunk_data = dynamic_offset - *previous_execution_data;
        /* printf("o %08lx=%08lx-%08lx\n", *chunk_data, dynamic_offset,
         *previous_execution_data); */
        *saved_offsets_and_reglog = dynamic_offset;
        chunk_data++, previous_execution_data++;
        saved_offsets_and_reglog++;
      }
      dynamic_offsets_by_map[map_index] = dynamic_offset;
    }

    addr = static_offset + (bunch->uses_dynamic_offset ? dynamic_offset : 0);

    if (!bunch->has_data) {
      effect_map_append(map, tstamp, addr, bunch->length, bunch->atoms);
    } else {
      effect_map_append_isodata(map, tstamp, addr, bunch->length,
                           bunch->atoms, bunch_data);
      bunch_data = align_to_pointer((uint8_t*)bunch_data + bunch->length);
    }
    ++bunch;
  }

  /* store reg-log delta */
  for (i = 0; i < reg_log_size; i += sizeof(uintptr_t)) {
    uintptr_t log_word = *bunch_data;
    *chunk_data = log_word - *previous_execution_data;
    /* printf("r %08lx=%08lx-%08lx\n", *chunk_data, log_word,
              *previous_execution_data); */
    *saved_offsets_and_reglog = log_word;
    chunk_data++, bunch_data++, previous_execution_data++;
    saved_offsets_and_reglog++;
  }

  cl->last_chunk_entry_visited = reg_log_entry_count;

  global_tstamp += r->instructions_retired;
}

static void pretty_print_init(CH_Record_Init* r) {
  const char* separator = "";
  fputs("INIT: ", pretty_print_out);
  if (r->flags & CH_INITFLAG_LOG_REG_READS) {
    fputs("LOG_REG_READS", pretty_print_out);
    separator = "|";
  }
  if (r->flags & CH_INITFLAG_LOG_MEM_READS) {
    fprintf(pretty_print_out, "%sLOG_MEM_READS", separator);
    separator = "|";
  }
  if (!separator) {
    fputc('0', pretty_print_out);
  }
  fputc('\n', pretty_print_out);
}

static void pretty_print_set_addr_map(CH_Record_SetAddrMap* r) {
  fprintf(pretty_print_out, "SET_ADDR_MAP: %08llx %llx",
          (unsigned long long)r->address, (unsigned long long)r->length);
  if (r->is_mapped) {
    fputs(" is_mapped", pretty_print_out);
  }
  if (r->is_read) {
    fputs(" is_read", pretty_print_out);
  }
  if (r->is_write) {
    fputs(" is_write", pretty_print_out);
  }
  if (r->is_execute) {
    fputs(" is_execute", pretty_print_out);
  }
  if (r->is_file) {
    fputs(" is_file", pretty_print_out);
  }
  if (r->suppress_debug_info) {
    fputs(" suppress_debug_info", pretty_print_out);
  }
  if (r->contents_will_follow) {
    fputs(" contents_will_follow", pretty_print_out);
  }
  if (r->contents_set_zero) {
    fputs(" contents_set_zero", pretty_print_out);
  }
  if (r->contents_from_file) {
    fputs(" contents_from_file", pretty_print_out);
  }
  if (r->contents_unchanged) {
    fputs(" contents_unchanged", pretty_print_out);
  }
  if (r->is_file) {
    fprintf(pretty_print_out, " %04llx:%08llx %08llx",
            (unsigned long long)r->device, (unsigned long long)r->inode,
            (unsigned long long)r->offset);
  }
  if (r->file_name_follows) {
    fprintf(pretty_print_out, " %s", (char*)(r + 1));
  }
  fputc('\n', pretty_print_out);
}

static void pretty_print_binary_string(uint8_t* data, uint32_t len) {
  uint32_t i;
  for (i = 0; i < len; ++i) {
    fprintf(pretty_print_out, "%02x", data[i]);
  }
}

static void pretty_print_binary(uint8_t* data, uint32_t len,
                                const char* prefix) {
  uint32_t i;
  int start_of_line = 1;
  for (i = 0; i < len; ++i) {
    if (start_of_line) {
      fputs(prefix, pretty_print_out);
      start_of_line = 0;
    }
    fprintf(pretty_print_out, "%02x", data[i]);
    if (i%36 == 35) {
      fputc('\n', pretty_print_out);
      start_of_line = 1;
    }
  }
  if (!start_of_line) {
    fputc('\n', pretty_print_out);
  }
}

static void pretty_print_bulk_write(CH_Record_BulkWrite* r) {
  fprintf(pretty_print_out, "BULK_WRITE: %08llx %x\n",
          (unsigned long long)r->address, r->length);
  pretty_print_binary((uint8_t*)(r + 1), r->length, "  ");
}

static void pretty_print_system_read(CH_Record_SystemRead* r) {
  fprintf(pretty_print_out, "SYSTEM_READ: %08llx %llx\n",
          (unsigned long long)r->address, (unsigned long long)r->length);
}

static void pretty_print_system_write(CH_Record_SystemWrite* r) {
  fprintf(pretty_print_out, "SYSTEM_WRITE: %08llx %llx\n",
          (unsigned long long)r->address, (unsigned long long)r->length);
}

static int16_t get_effect_immediate(CH_RegEffect* e) {
  return (int16_t)((e->imm1 << 8) | e->imm0);
}

static char* get_register_name(uint32_t reg, uint8_t bytes_pow2,
                               char buf[8]) {
#ifdef CH_X86
  static char* gp_names[8] =
    { "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI" };

  switch (get_register_type(reg)) {
  case CH_REGTYPE_GP:
    if (reg < 8) {
      switch (bytes_pow2) {
      case 0:
        if (reg < 4) {
          sprintf(buf, "%cL", gp_names[reg][0]);
        } else {
          return gp_names[reg];
        }
        break;
      case 1:
        return gp_names[reg];
      case 2:
        sprintf(buf, "E%s", gp_names[reg]);
        break;
      case 3:
        sprintf(buf, "R%s", gp_names[reg]);
        break;
      default:
        fatal_error(7, "Unknown size %d", 1<<bytes_pow2);
      }
    } else {
      sprintf(buf, "R%d", reg);
    }
    return buf;

  case CH_REGTYPE_X86_SSE:
    sprintf(buf, "XMM%d", reg - CH_X86_SSE_REGS);
    return buf;

  case CH_REGTYPE_X86_FP:
    sprintf(buf, "FP%d", reg - CH_X86_FP_REGS);
    return buf;
    
  case CH_REGTYPE_X86_FPTOP:
    return "FPTOP";

  default:
    return "???";
  }
#else
#error Unknown architecture
#endif
}

static void pretty_print_regs(int reg, int num, int bytes_pow2, void* data) {
  int i;
  char buf[8];

  fputc(' ', pretty_print_out);
  for (i = 0; i < num; ++i) {
    char* reg_name = get_register_name(reg + i, bytes_pow2, buf);
    switch (bytes_pow2) {
    case 2:
      fprintf(pretty_print_out, " %3s=%08x",
              reg_name, ((uint32_t*)data)[i]);
      break;
    case 3:
      fprintf(pretty_print_out, " %3s=%08llx",
              reg_name, ((unsigned long long*)data)[i]);
      break;
    case 4:
      /* XXX assumes little-endian */
      fprintf(pretty_print_out, " %3s=%016llx%016llx",
              reg_name, ((unsigned long long*)data)[2*i+1],
              ((unsigned long long*)data)[2*i]);
      break;
    default:
      fatal_error(2, "Unknown register size: %d", bytes_pow2);
    }
  }
  fputc('\n', pretty_print_out);
}

static void pretty_print_reset_state(CH_Record_ResetState* r) {
  int i;

  fprintf(pretty_print_out, "RESET_STATE: thread_ID=%d, SP_max=%llx\n",
          r->thread_ID, (long long)r->SP_max);
#ifdef CH_X86
  for (i = 0; i < 8; i += 4) {
    pretty_print_regs(i, 4, CH_PTR_LOG2_BYTES, &r->context.regs_GP[i]);
  }
#if __WORDSIZE == 64
  for (i = 8; i < 16; i += 4) {
    pretty_print_regs(i, 4, CH_PTR_LOG2_BYTES, &r->context.regs_GP[i]);
  }
#endif
  for (i = 0; i < 8; i += 2) {
    pretty_print_regs(i + CH_X86_SSE_REGS, 2, 4, &r->context.regs_SSE[i]);
  }
#if __WORDSIZE == 64
  for (i = 8; i < 16; i += 2) {
    pretty_print_regs(i + CH_X86_SSE_REGS, 2, 4, &r->context.regs_SSE[i]);
  }
#endif
  for (i = 0; i < 8; i += 2) {
    pretty_print_regs(i + CH_X86_FP_REGS, 2, 3, &r->context.regs_FP[i]);
  }
  fprintf(pretty_print_out, "  FPTOP=%d\n", r->context.FP_top & 7);
#else
#error Unknown architecture
#endif
}

static void pretty_print_exec(CH_Record_Exec* r, CodeClosure* cl) {
  int i;
  uintptr_t* data = align_to_pointer(r + 1);
  CH_BunchedEffect* bunch = (CH_BunchedEffect*)(cl + 1);

  fprintf(pretty_print_out, "EXEC#%d: TStamp %lld; %d retired (out of %d)\n",
          r->header.code_index, (long long)global_tstamp,
          r->instructions_retired, cl->num_instructions);
  for (i = 0; i < cl->num_bunched_effects; ++i) {
    if (bunch[i].has_dynamic_offset) {
      fprintf(pretty_print_out, "  Bunch %d offset: %08llx\n", i,
              (unsigned long long)*data);
      data++;
    }
  }
  for (i = 0; i < cl->num_bunched_effects; ++i) {
    if (bunch[i].has_data) {
      uint8_t* bunch_data = (uint8_t*)data;

      fprintf(pretty_print_out, "  Bunch %d data: ", i);
      pretty_print_binary_string(bunch_data, bunch[i].length);
      data = align_to_pointer(bunch_data + bunch[i].length);
      fputc('\n', pretty_print_out);
    }
  }
  fprintf(pretty_print_out, "  Register log:\n");
  pretty_print_binary((uint8_t*)data, cl->reg_log_size, "    ");
}

static void pretty_print_define_code(CH_Record_DefineCode* r) {
  int i, j;
  CH_BunchedEffect* bunched_effect_ptr;
  CH_RegEffect* reg_effect_ptr;
  static const char* map_names[4] = {
    "INSTR_EXEC", "MEM_READ", "MEM_WRITE", "ENTER_SP"
  };

  fprintf(pretty_print_out, "DEFINE_CODE: #%d instrs=%d reglog=%d\n",
          r->code_index, r->num_instructions, r->reg_log_size);
  bunched_effect_ptr = (CH_BunchedEffect*)align_to_pointer(r + 1);
  reg_effect_ptr = (CH_RegEffect*)(bunched_effect_ptr + r->num_bunched_effects);

  for (i = 0; i < r->num_bunched_effects; ++i) {
    uintptr_t offset = bunched_effect_ptr->static_offset;
    fprintf(pretty_print_out, "  %s %d-%d:%s%s\n",
            map_names[bunched_effect_ptr->map],
            bunched_effect_ptr->first_instruction_index,
            bunched_effect_ptr->last_instruction_index,
            bunched_effect_ptr->has_dynamic_offset ? " has_dynamic_offset" : "",
            bunched_effect_ptr->uses_dynamic_offset ? " uses_dynamic_offset" : "");
    for (j = 0; j < CH_EFFECT_ATOMS; ++j) {
      CH_BunchedEffectAtom* atom = &bunched_effect_ptr->atoms.atoms[j];
      if (atom->length_increment) {
        fprintf(pretty_print_out, "    #%d: %08llx (%d)\n",
                atom->instruction_index + bunched_effect_ptr->first_instruction_index,
                (unsigned long long)offset, atom->length_increment);
        offset += atom->length_increment;
      }
    }
    ++bunched_effect_ptr;
  }

  for (i = 0; i < r->num_reg_effects; ++i) {
    int bytes = 1 << reg_effect_ptr->bytes_pow2;
    char buf1[8], buf2[8];
    char* reg_name = get_register_name(reg_effect_ptr->reg,
                                       reg_effect_ptr->bytes_pow2, buf1);
    fprintf(pretty_print_out, "  #%d ", reg_effect_ptr->instruction_index);
    switch (reg_effect_ptr->type) {
    case CH_EFFECT_REG_READ:
      fprintf(pretty_print_out, "REG_READ%d(%s)\n", bytes, reg_name);
      break;
    case CH_EFFECT_REG_WRITE:
      fprintf(pretty_print_out, "REG_WRITE%d(%s)\n", bytes, reg_name);
      break;
    case CH_EFFECT_DYNREG_READ:
      fprintf(pretty_print_out, "DYNREG_READ%d(%s)\n", bytes, reg_name);
      break;
    case CH_EFFECT_DYNREG_WRITE:
      fprintf(pretty_print_out, "DYNREG_WRITE%d(%s)\n", bytes, reg_name);
      break;
    case CH_EFFECT_REG_SETCONST:
      fprintf(pretty_print_out, "REG_SETCONST%d(%s,%x)\n", bytes,
              reg_name, get_effect_immediate(reg_effect_ptr));
      break;
    case CH_EFFECT_REG_ADDCONST:
      fprintf(pretty_print_out, "REG_ADDCONST%d(%s,%x)\n", bytes,
              reg_name, get_effect_immediate(reg_effect_ptr));
      break;
    case CH_EFFECT_REG_ADDREG:
      fprintf(pretty_print_out, "REG_ADDREG%d(%s,%s,%x)\n", bytes,
              reg_name, get_register_name(reg_effect_ptr->imm1,
                                          reg_effect_ptr->bytes_pow2, buf2),
              (int8_t)reg_effect_ptr->imm0);
      break;
    default:
      fprintf(pretty_print_out, "Unknown%d#%d\n", bytes, reg_effect_ptr->type);
    }
    ++reg_effect_ptr;
  }
}

static void dummy_exec_handler(CH_RecordHeader* header, void* closure) {
  CH_Record_Exec* r = (CH_Record_Exec*)header;
  global_tstamp += r->instructions_retired;  
}

static void pretty_print_record(CH_RecordHeader* record) {
  RecordHandlerClosure* h = &record_handlers[record->code_index];
  if (record->code_index >= record_handler_size || !h->handler) {
    h = NULL;
  }

  fprintf(pretty_print_out, "%08llx ",
          (unsigned long long)pretty_print_offset);
  if (h && (h->handler == exec_handler || h->handler == dummy_exec_handler)) {
    pretty_print_exec((CH_Record_Exec*)record, h->closure);
  } else {
    switch (record->code_index) {
    case CH_INIT:
      pretty_print_init((CH_Record_Init*)record);
      break;
    case CH_SET_ADDR_MAP:
      pretty_print_set_addr_map((CH_Record_SetAddrMap*)record);
      break;
    case CH_BULK_WRITE:
      pretty_print_bulk_write((CH_Record_BulkWrite*)record);
      break;
    case CH_SYSTEM_READ:
      pretty_print_system_read((CH_Record_SystemRead*)record);
      break;
    case CH_SYSTEM_WRITE:
      pretty_print_system_write((CH_Record_SystemWrite*)record);
      break;
    case CH_RESET_STATE:
      pretty_print_reset_state((CH_Record_ResetState*)record);
      break;
    case CH_DEFINE_CODE:
      pretty_print_define_code((CH_Record_DefineCode*)record);
      break;
    default:
      fprintf(pretty_print_out, "#%d (%d):\n", record->code_index, record->length);
      pretty_print_binary((uint8_t*)(record + 1),
                          record->length - (uint32_t)sizeof(*record), "  ");
      fputc('\n', pretty_print_out);
    }
  }

  pretty_print_offset += record->length;
}

static void handle_record(CH_RecordHeader* record) {
  RecordHandlerClosure* h = &record_handlers[record->code_index];

  if (pretty_print_out) {
    pretty_print_record(record);
  }

  if (record->code_index >= record_handler_size || !h->handler)
    return;

  /* Eat a probable branch mispredict here */
  h->handler(record, h->closure);
}

static void process_trace_buffer(const void* data, int len) {
  const void* end = (char*)data + len;
  CH_RecordHeader* header = (CH_RecordHeader*)data;
  uintptr_t rec_len;
  
  while (1) {
    char* err = NULL;
    const void* next = NULL;
    rec_len = header->length;

    /* The 'length' field could be corrupt. */
    if (rec_len < sizeof(CH_RecordHeader)) {
      err = "Undersized";
    } else if (rec_len & (sizeof(void*)-1)) {
      err = "Unaligned";
    } else {
      next = (char*)header + rec_len;
      if (next <= (void*)header || next > end) {
        err = "Oversized";
      }
    }
    if (err)
      fatal_error(29, "%s length (%p at %llx)!", err, (void*)rec_len,
                  (unsigned long long)(save_offset + ((char*)header - (char*)data)));

    if (header->code_index == CH_END_BUFFER) {
      // We don't want to save this record to a saved trace
      rec_len = 0;
      break;
    }

    handle_record(header);
    if (next == end)
      break;
    header = (CH_RecordHeader*)next;
  }
  
  if (save_file) {
    int total_len = ((char*)header + rec_len) - (char*)data;
    int written = write(save_fd, data, total_len);
    if (written < total_len)
      fatal_perror(1, "Cannot write to log file");
  
    save_offset += total_len;
  }
}

static void open_save_file() {
  if (save_file) {
    save_fd = open(save_file,
                   O_CREAT | O_TRUNC | O_APPEND | O_LARGEFILE | O_WRONLY,
                   S_IRWXU);
    if (save_fd < 0)
      fatal_perror(1, "Cannot open log file");
  }
}

static void process_slave_trace() {
  int fd, r;
  CH_TraceHeader* buffer;

  umask(077);
  fd = mkstemp(tmp_name);
  close(fd);
  fd = open(tmp_name, O_RDWR);
  if (fd < 0)
    fatal_perror(1, "Cannot open temp file");

  atexit(unlink_tmp);

  r = ftruncate(fd, trace_buf_len*(trace_buf_count + 1));
  if (r < 0)
    fatal_perror(1, "Cannot set file size");

  buffer = mmap(NULL, trace_buf_len*(trace_buf_count + 1), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if (!buffer)
    fatal_perror(1, "Cannot mmap file");

  close(fd);

  write_control(tmp_name, strlen(tmp_name) + 1);
  /* set up list of buffers, pushing them into the pipe for use by the tracer */
  for (r = 0; r < trace_buf_count; ++r) {
    uintptr_t msg[2] = { (r + 1)*trace_buf_len, trace_buf_len };
    write_control(msg, sizeof(msg));
  }

  /* From here on, anything we get from the tracer is suspect. */
  for (;;) {
    uintptr_t msg[2];
    if (read_control(&msg, sizeof(msg))) {
      if (msg[0]%trace_buf_len != 0 || msg[1] != trace_buf_len ||
          msg[0] < trace_buf_len ||
          msg[0] > trace_buf_count*trace_buf_len) {
        fprintf(stderr, "Corrupted message: %x, %x\n", (unsigned int)msg[0],
                (unsigned int)msg[1]);
        break;
      }
      process_trace_buffer((char*)buffer + msg[0], msg[1]);
      /* Return the buffer to the tracer */
      write_control(msg, sizeof(msg));
    } else {
      /* The indexer has terminated. */
      uint32_t length;
      uintptr_t buf_end = buffer->offsets.buffer_start + buffer->offsets.buffer_length;
      if (buffer->offsets.buffer_start%trace_buf_len != 0 ||
          buffer->offsets.buffer_length != trace_buf_len ||
          buffer->offsets.buffer_start < trace_buf_len ||
          buffer->offsets.buffer_start > trace_buf_count*trace_buf_len ||
          buffer->last_record < buffer->offsets.buffer_start ||
          buffer->last_record > buf_end - sizeof(CH_RecordHeader)) {
        fprintf(stderr, "Corrupted header\n");
        break;
      }
      length = ((CH_RecordHeader*)((char*)buffer + buffer->last_record))->length;
      if (buf_end > buffer->last_record + length) {
        buf_end = buffer->last_record + length;
      }
      if (!save_file) {
        save_file = "/tmp/lastseg";
        open_save_file();
      }
      process_trace_buffer((char*)buffer + buffer->offsets.buffer_start,
                           buf_end - buffer->offsets.buffer_start);
      break;
    }
  }
}

static void process_input_trace(int input_fd) {
  void* buffer = safe_malloc(trace_buf_len);
  int offset = 0;

  for (;;) {
    int bytes_read = read(input_fd, (char*)buffer + offset, trace_buf_len - offset);
    int buf_len = offset + bytes_read;
    void* record_ptr = buffer;
    if (bytes_read < 0)
      fatal_perror(4, "Cannot read from trace!");
    if (bytes_read == 0)
      break;

    for (;;) {
      CH_RecordHeader* r = (CH_RecordHeader*)record_ptr;
    
      if (buf_len < sizeof(CH_RecordHeader))
        break;
      if (buf_len < r->length)
        break;
      handle_record(r);
      record_ptr = (char*)record_ptr + r->length;
      buf_len -= r->length;
    }

    memmove(buffer, record_ptr, buf_len);
    offset = buf_len;
  }

  safe_free(buffer);
}

static void init_handler(CH_RecordHeader* header, void* closure) {
  CH_Record_Init* r = (CH_Record_Init*)header;
  trace_control_flags = r->flags;
}

static void set_addr_map_handler(CH_RecordHeader* header, void* closure) {
  CH_Record_SetAddrMap* r = (CH_Record_SetAddrMap*)header;
  CH_DBAddrMapEntry* entry;
  
  ensure_buffer_size(&address_map_buffer,
                     (address_map_buffer_count + 1)*sizeof(CH_DBAddrMapEntry));
  entry = (CH_DBAddrMapEntry*)address_map_buffer.data +
    address_map_buffer_count;
  address_map_buffer_count++;
  
  entry->tstamp = global_tstamp;
  entry->address = r->address;
  entry->length = r->length;
  entry->is_mapped = r->is_mapped;
  entry->is_read = r->is_read;
  entry->is_write = r->is_write;
  entry->is_execute = r->is_execute;
  entry->is_file = r->is_file;
  entry->suppress_debug_info = r->suppress_debug_info;
  entry->contents_from_file = r->contents_from_file;
  entry->contents_set_zero = r->contents_set_zero;
  entry->contents_unchanged = r->contents_unchanged;
  entry->contents_will_follow = r->contents_will_follow;
  memset(entry->reserved_zero, 0, sizeof(entry->reserved_zero));
  entry->device = r->device;
  entry->inode = r->inode;
  entry->offset = r->offset;
  if (r->file_name_follows) {
    entry->filename_len = strlen((char*)(r + 1));
    entry->filename_fileloc = db_append_sync(&db, r + 1, entry->filename_len);
  } else {
    entry->filename_len = 0;
    entry->filename_fileloc = 0;
  }
}

static void bulk_write_handler(CH_RecordHeader* header, void* closure) {
  CH_Record_BulkWrite* r = (CH_Record_BulkWrite*)header;
  effect_map_append_isodata(&builtin_maps[CH_MAP_MEM_WRITE], global_tstamp,
                       r->address, r->length, zero_atoms, r + 1);
}

static void system_read_handler(CH_RecordHeader* header, void* closure) { 
  CH_Record_SystemRead* r = (CH_Record_SystemRead*)header;
  effect_map_append(&builtin_maps[CH_MAP_MEM_READ], global_tstamp,
               r->address, r->length, zero_atoms);
}

static void system_write_handler(CH_RecordHeader* header, void* closure) {
  /* don't need to do anything; the bulk-write records will handle it */
}

typedef struct {
  void* data;
  uint32_t size;
  uint32_t set_index;
} WriteEffectClosure;

static int effect_writer_run_count;

static void effect_writer(void* closure) {
  WriteEffectClosure* cl = closure;
  CH_CompressorState compress;
  uint64_t offset;
  CH_DBEffectSetEntry* entry;

  compress_init(&compress, CH_COMPRESSTYPE_DATA);
  compress_data(&compress, cl->data, cl->size);
  safe_free(cl->data);
  compress_done(&compress);

  offset = db_append_sync(&db, compress.output.data, compress.output_len);
  {
    char buf[1024];
    sprintf(buf, "effects%d", effect_writer_run_count++);
    compress_finish(&compress, buf);
  }

  pthread_mutex_lock(&effect_set_entry_mutex);
  entry = &((CH_DBEffectSetEntry*)effect_set_entries.data)[cl->set_index];
  entry->fileloc = offset;
  entry->compressed_size = compress.output_len;
  pthread_mutex_unlock(&effect_set_entry_mutex);

  semaphore_remove(&effect_set_entry_semaphore);
  safe_free(cl);
}

static void flush_effect_set() {
  WriteEffectClosure* clm = safe_malloc(sizeof(WriteEffectClosure));
  WriteEffectClosure cl = { effect_set, effect_set_used,
                            effect_set_entry_count };

  *clm = cl;
  pthread_mutex_lock(&effect_set_entry_mutex);
  ensure_buffer_size(&effect_set_entries,
                     sizeof(CH_DBEffectSetEntry)*(effect_set_entry_count + 1));
  pthread_mutex_unlock(&effect_set_entry_mutex);

  ++effect_set_entry_count;
  effect_set = NULL;
  effect_set_used = 0;
  semaphore_add(&effect_set_entry_semaphore);
  run_on_thread(effect_writer, clm);
}

static void append_code_info(uint32_t code_index,
                             void* effect_data,
                             uint16_t num_bunched_effects,
                             uint16_t num_reg_effects) {
  CH_DBCodeInfoEntry* entry;
  uint32_t effect_size =
    align_size_to_pointer(sizeof(CH_BunchedEffect)*num_bunched_effects
                          + sizeof(CH_RegEffect)*num_reg_effects);

  if (effect_set_used + effect_size > CH_EFFECT_SET_SIZE) {
    flush_effect_set();
    if (!effect_set) {
      effect_set = safe_malloc(CH_EFFECT_SET_SIZE);
    }
  }

  if (code_index < code_info_entries_count)
    fatal_error(33, "Code indexes out of order");

  code_info_entries_count = code_index + 1;

  memcpy(effect_set + effect_set_used, effect_data, effect_size);

  ensure_buffer_size(&code_info_entries,
                     code_info_entries_count*sizeof(CH_DBCodeInfoEntry));
  
  entry = &((CH_DBCodeInfoEntry*)(code_info_entries.data))[code_index];
  entry->effect_set = effect_set_entry_count;
  entry->offset_in_effect_set = effect_set_used;
  entry->num_bunched_effects = num_bunched_effects;
  entry->num_reg_effects = num_reg_effects;

  effect_set_used += effect_size;
}

static void finish_code_info() {
  uint64_t code_info_offset;
  uint32_t code_info_size =
    code_info_entries_count*sizeof(CH_DBCodeInfoEntry);
  uint64_t effect_set_entries_offset;
  uint32_t effect_set_size =
    effect_set_entry_count*sizeof(CH_DBEffectSetEntry);

  semaphore_wait_for_all_removed(&effect_set_entry_semaphore);

  code_info_offset =
    db_append_sync(&db, code_info_entries.data, code_info_size);
  effect_set_entries_offset =
    db_append_sync(&db, effect_set_entries.data, effect_set_size);

  db_add_directory_entry(&db, CH_SECTION_CODE_INFO, code_info_offset, code_info_size);
  db_add_directory_entry(&db, CH_SECTION_EFFECT_SET, effect_set_entries_offset,
                         effect_set_size);
}

static uint16_t count_bunched_effect_offsets(CH_Record_DefineCode* r) {
  int i;
  int num_bunched_effects = r->num_bunched_effects;
  uint16_t total = 0;
  CH_BunchedEffect* bunched_effects = (CH_BunchedEffect*)
    align_to_pointer(r + 1);

  for (i = 0; i < num_bunched_effects; ++i) {
    total += bunched_effects[i].has_dynamic_offset;
  }
  return total;
}

static uint64_t compute_modified_registers_mask(CH_RegEffect* e, int count) {
  uint64_t r = 0;
  int i;
  for (i = 0; i < count; ++i) {
    switch (e->type) {
      case CH_EFFECT_REG_WRITE:
      case CH_EFFECT_REG_SETCONST:
      case CH_EFFECT_REG_ADDCONST:
      case CH_EFFECT_REG_ADDREG:
        r |= 1L << e->reg;
        break;
      case CH_EFFECT_DYNREG_WRITE:
        /* on X86/AMD64, this is only used to address the FP registers */
        r |= (((uint64_t)1 << CH_X86_FP_REGS_COUNT) - 1) << CH_X86_FP_REGS;
        break;
      default:
        break;
    }
    ++e;
  }
  return r;
}

static void define_code_handler(CH_RecordHeader* header, void* closure) {
  CH_Record_DefineCode* r = (CH_Record_DefineCode*)header;
  uint32_t bunched_effects_size =
    sizeof(CH_BunchedEffect)*r->num_bunched_effects;
  uint16_t num_instructions = r->num_instructions;
  uint16_t num_reg_effects = r->num_reg_effects;
  uint16_t num_bunched_effects = r->num_bunched_effects;
  uint16_t reg_log_size = r->reg_log_size;
  CH_BunchedEffect* bunched_effects = (CH_BunchedEffect*)
    align_to_pointer(r + 1);
  uint16_t num_bunched_effect_offsets = count_bunched_effect_offsets(r);
  CodeClosure* cl =
    safe_malloc(sizeof(CodeClosure) + bunched_effects_size +
                (CH_SAVE_INSTRUCTION_DYNAMIC_OFFSETS ?
                 num_bunched_effect_offsets*sizeof(uintptr_t) : 0) +
                reg_log_size);
 
  cl->num_instructions = num_instructions;
  cl->num_bunched_effects = num_bunched_effects;
  cl->bunched_offsets_count = num_bunched_effect_offsets;
  cl->reg_log_size = reg_log_size;
  cl->registers_maybe_modified =
    compute_modified_registers_mask((CH_RegEffect*)(bunched_effects + num_bunched_effects),
                                    num_reg_effects);
  cl->last_chunk_entry_visited = (uintptr_t)-1;
  if (align_size_to_pointer(reg_log_size) != reg_log_size)
    fatal_error(33, "bad reg log size");

  memcpy(cl + 1, bunched_effects, bunched_effects_size);

  if (db_file) {
    append_code_info(r->code_index, bunched_effects,
                     r->num_bunched_effects, num_reg_effects);
  }
  
  set_record_handler(r->code_index, closure, cl);
}

typedef struct {
  void* instructions_retired_data;
  uintptr_t instructions_retired_len;
  void* code_index_data;
  uintptr_t code_index_len;
  void* chunk_data;
  uintptr_t chunk_len;
  uintptr_t SP_max;
  CH_TStamp chunk_tstamp;
  uint64_t registers_maybe_modified;
  uint32_t pthread_cookie;
  uint32_t entry_index;
  CH_DBRegLogChunk chunk_header;
} WriteRegLogClosure;

static int reg_log_writer_run_count;

static uint32_t pad_compression(CH_CompressorState* compress, uint32_t offset,
                                uint32_t pad) {
  uint32_t delta = offset%pad;
  if (delta == 0)
    return offset;
  delta = pad - delta;
  offset += delta;
  while (delta > 0) {
    uint32_t len = delta;
    if (len > 0x10000) {
      len = 0x10000;
    }
    compress_data(compress, zeroes, len);
    delta -= len;
  }
  return offset;
}

static void reg_log_writer(void* closure) {
  WriteRegLogClosure* cl = closure;
  CH_CompressorState compress;
  uint64_t offset;
  CH_DBRegLogEntry* entry;
  CH_TStamp first_tstamp = cl->chunk_tstamp;
  uint32_t buf_offset;

  cl->chunk_header.num_codes_executed = cl->instructions_retired_len;

  compress_init(&compress, CH_COMPRESSTYPE_DATA);
  compress_data(&compress, &cl->chunk_header, sizeof(cl->chunk_header));
  compress_data(&compress, cl->instructions_retired_data,
                cl->instructions_retired_len);
  safe_free(cl->instructions_retired_data);
  buf_offset = sizeof(cl->chunk_header) + cl->instructions_retired_len;
  buf_offset = pad_compression(&compress, buf_offset, sizeof(uint32_t));
  compress_data(&compress, cl->code_index_data, cl->code_index_len);
  safe_free(cl->code_index_data);
  buf_offset += cl->code_index_len;
  pad_compression(&compress, buf_offset, sizeof(uintptr_t));
  compress_data(&compress, cl->chunk_data, cl->chunk_len);
  safe_free(cl->chunk_data);
  compress_done(&compress);

  offset = db_append_sync(&db, compress.output.data, compress.output_len);
  {
    char buf[1024];
    sprintf(buf, "reglog%d", reg_log_writer_run_count++);
    compress_finish(&compress, buf);
  }

  pthread_mutex_lock(&reg_log_entry_mutex);
  ensure_buffer_size(&reg_log_entry,
                     sizeof(CH_DBRegLogEntry)*(cl->entry_index + 1));
  entry = &((CH_DBRegLogEntry*)reg_log_entry.data)[cl->entry_index];
  entry->reg_log_chunk_fileloc = offset;
  entry->reg_log_chunk_compressed_size = compress.output_len;
  entry->registers_maybe_modified = cl->registers_maybe_modified;
  entry->SP_max = cl->SP_max;
  entry->pthread_cookie = cl->pthread_cookie;
  entry->first_tstamp = first_tstamp;
  /* hold the lock until we've finished writing to the entry, otherwise
     some other thread might reallocate the array under us */
  pthread_mutex_unlock(&reg_log_entry_mutex);

  semaphore_remove(&reg_log_entry_semaphore);
  safe_free(cl);
}

static void flush_reg_log(uintptr_t SP_max) {
  WriteRegLogClosure* clm = safe_malloc(sizeof(WriteRegLogClosure));
  WriteRegLogClosure cl = { reg_log_instructions_retired.data,
                            reg_log_code_index_count,
                            reg_log_code_indexes.data,
                            reg_log_code_index_count*sizeof(uint32_t),
                            reg_log_chunk.data, reg_log_chunk_used,
                            SP_max,
                            reg_log_chunk_tstamp,
                            registers_maybe_modified,
                            reg_log_pthread_cookie,
                            reg_log_entry_count,
                            reg_log_chunk_header };

  *clm = cl;

  ++reg_log_entry_count;
  reg_log_instructions_retired.data = NULL;
  reg_log_instructions_retired.size = 0;
  reg_log_code_indexes.data = NULL;
  reg_log_code_indexes.size = 0;
  reg_log_code_index_count = 0;
  reg_log_chunk.data = NULL;
  reg_log_chunk.size = 0;
  reg_log_chunk_used = 0;
  registers_maybe_modified = 0;

  semaphore_add(&reg_log_entry_semaphore);
  run_on_thread(reg_log_writer, clm);
}

static void reset_state_handler(CH_RecordHeader* header, void* closure) {
  CH_Record_ResetState* r = (CH_Record_ResetState*)header;

  if (reg_log_chunk.data) {
    flush_reg_log(r->SP_max);
  }

  /* make the buffer nice and big, we're going to thrash it */
  ensure_buffer_size(&reg_log_chunk, 100000);
  ensure_buffer_size(&reg_log_instructions_retired, 10000);
  ensure_buffer_size(&reg_log_code_indexes, 40000);

  reg_log_chunk_tstamp = global_tstamp;
  reg_log_chunk_header.initial_context = r->context;
  reg_log_pthread_cookie = r->thread_ID;
}

static void finish_reg_log() {
  uint64_t reg_log_entries_offset;
  uint32_t reg_log_entries_size =
    reg_log_entry_count*sizeof(CH_DBRegLogEntry);

  semaphore_wait_for_all_removed(&reg_log_entry_semaphore);

  reg_log_entries_offset =
    db_append_sync(&db, reg_log_entry.data, reg_log_entries_size);

  db_add_directory_entry(&db, CH_SECTION_REG_LOG, reg_log_entries_offset,
                         reg_log_entries_size);
}

static void dummy_handler(CH_RecordHeader* header, void* closure) {
}

static void init_record_handlers() {
  set_record_handler(CH_INIT, init_handler, NULL);
  if (db_file) {
    set_record_handler(CH_SET_ADDR_MAP, set_addr_map_handler, NULL);
    set_record_handler(CH_BULK_WRITE, bulk_write_handler, NULL);
    set_record_handler(CH_SYSTEM_READ, system_read_handler, NULL);
    set_record_handler(CH_SYSTEM_WRITE, system_write_handler, NULL);
    set_record_handler(CH_DEFINE_CODE, define_code_handler, exec_handler);
    set_record_handler(CH_RESET_STATE, reset_state_handler, NULL);
  } else {
    set_record_handler(CH_SET_ADDR_MAP, dummy_handler, NULL);
    set_record_handler(CH_BULK_WRITE, dummy_handler, NULL);
    set_record_handler(CH_SYSTEM_READ, dummy_handler, NULL);
    set_record_handler(CH_SYSTEM_WRITE, dummy_handler, NULL);
    set_record_handler(CH_DEFINE_CODE, define_code_handler,
                       dummy_exec_handler);
    set_record_handler(CH_RESET_STATE, dummy_handler, NULL);
  }
}

static void allocate_zeroes() {
  zeroes = malloc(1<<16);
  memset(zeroes, 0, 1<<16);
}

int main(int argc, char** argv) {
  int i;

  init_utils();
  init_threads(CH_WORKER_THREADS);
  compress_global_init();
  allocate_zeroes();

  signal(SIGPIPE, SIG_IGN);

  parse_options(argc, argv);

  open_save_file();

  if (db_file) {
    db_fd = open(db_file,
                 O_CREAT | O_TRUNC | O_LARGEFILE | O_WRONLY,
                 S_IRWXU);
    if (db_fd < 0)
      fatal_perror(1, "Cannot open db file");

    db_init(&db, db_fd);
    for (i = 0; i <= CH_MAX_BUILTIN_MAP; ++i) {
      /* Try to get around 100K worth of (compressed) accesses per chunk.
         16 bytes per access at an assumed 10:1 compression ratio... */
      effect_map_init(&builtin_maps[i], i, &db, 60000);
    }
    pthread_mutex_init(&effect_set_entry_mutex, NULL);
    semaphore_init(&effect_set_entry_semaphore);
    semaphore_init(&reg_log_entry_semaphore);
    pthread_mutex_init(&reg_log_entry_mutex, NULL);

    ensure_buffer_size(&code_info_entries, sizeof(CH_DBCodeInfoEntry)*100);
    memset(code_info_entries.data, 0, sizeof(CH_DBCodeInfoEntry)*100); 

    effect_set = safe_malloc(CH_EFFECT_SET_SIZE);
  }

  init_record_handlers();

  if (read_trace_from_input) {
    process_input_trace(0);
  } else {
    process_slave_trace();
  }

  if (db_file) {
    CH_DBHeader header_template;
    uint64_t addr_map_offset = db_append_sync(&db, address_map_buffer.data,
                                              address_map_buffer_count*sizeof(CH_DBAddrMapEntry));
    db_add_directory_entry(&db, CH_SECTION_ADDR_MAP, addr_map_offset,
                           address_map_buffer_count*sizeof(CH_DBAddrMapEntry));

    for (i = 0; i <= CH_MAX_BUILTIN_MAP; ++i) {
      effect_map_prefinish(&builtin_maps[i]);
    }
    flush_effect_set();
    /* we don't know what the true SP_max is. Just set it to the maximum possible
       value. */
    flush_reg_log((uintptr_t)-1);

    for (i = 0; i <= CH_MAX_BUILTIN_MAP; ++i) {
      effect_map_finish(&builtin_maps[i], builtin_map_names[i]);
    }
    finish_code_info();
    finish_reg_log();

    header_template.dynamic_offsets_in_reg_log =
      CH_SAVE_INSTRUCTION_DYNAMIC_OFFSETS;
    header_template.have_reg_reads =
      (trace_control_flags & CH_INITFLAG_LOG_REG_READS) != 0;
    header_template.have_mem_reads =
      (trace_control_flags & CH_INITFLAG_LOG_MEM_READS) != 0;
    header_template.effect_map_page_size_bits = CH_EFFECT_MAP_PAGE_SIZE_BITS;
    header_template.end_tstamp = global_tstamp;
    db_close(&db, &header_template);
  }

  return 0;
}
