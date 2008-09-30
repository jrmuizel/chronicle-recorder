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

/*
 * This is the Chronicle tracer, a Valgrind tool for complete recording of
 * a process's execution. It spawns a helper "indexer" process and sends
 * the recording data to it using the protocol described in ct_logstream.h.
 */

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_vki.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_aspacemgr.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_debuginfo.h"
#include "libvex_guest_amd64.h"
#include "libvex_guest_x86.h"

#include "log_stream.h"

/* Architecture-specific Valgrind defines */
#if defined(VGA_x86)
typedef VexGuestX86State VexGuestState;
#define VexGuestState_SP guest_ESP
#elif defined(VGA_amd64)
typedef VexGuestAMD64State VexGuestState;
#define VexGuestState_SP guest_RSP
#else
#error Unknown architecture
#endif

/** File descriptors to communicate with the indexer */
static Int write_to_indexer_fd;
static Int read_from_indexer_fd;
/** The shared memory area shared with the indexer */
static CH_TraceHeader* trace_buffer_base;
static OffT            trace_buffer_size;
/** The current sub-area of the shared memory that we are filling with our data */
static void* trace_buffer;
static void* trace_buffer_end;

/** Tracks the maximum guest SP value since the start of the current epoch */
static uintptr_t SP_max;

/** Do a state reset every 20,000 basic blocks */
static Int state_reset_period = 20000;
/** Reset the state when this hits zero */
static Int state_reset_countdown = 0;
/** The thread ID for the last executed block; use this to detect thread switches */
static ThreadId last_thread = -1;
/** Some combination of CH_INITFLAG_s. */
static Int control_flags = 0;
/**
 * Sometimes we need to be able to dynamically turn off tracing,
 * e.g., currently, in a forked child. This records whether we have turned it
 * off in this process.
 */
static Bool tracing_enabled;

/** Cached architecture-specific IR constants (could be 32bit or 64bit variants) */
static IRType     IR_ptr_type;
static IRConstTag IR_ptr_const;
static IROp       IR_ptr_add;
static IROp       IR_ptr_sub;
static IREndness  IR_end;
/** A magic IR_const value that we use for our own signalling */
static IRConst*   IR_const_INVALID = (IRConst*)0x1;

static IRSB* bb_in_debug;

#if 0
/* Useful debugging support */
static uintptr_t watch;
static IRExpr* watch_expr;
#define watch_t void*
#define WATCH(n) do { if (watch) { VG_(printf)("WATCH %d: %p => %p\n", n, watch, *(watch_t*)watch); } if (watch_expr) {ppIRExpr(watch_expr); VG_(printf)("\n"); } } while (0)
#endif

static void init_IR_constants(void)
{
#if VG_WORDSIZE == 8
  IR_ptr_type = Ity_I64;
  IR_ptr_const = Ico_U64;
  IR_ptr_add = Iop_Add64;
  IR_ptr_sub = Iop_Sub64;
#else
  IR_ptr_type = Ity_I32;
  IR_ptr_const = Ico_U32;
  IR_ptr_add = Iop_Add32;
  IR_ptr_sub = Iop_Sub32;
#endif
#if defined(VG_BIGENDIAN)
  IR_end = Iend_BE;
#else
  IR_end = Iend_LE;
#endif
}

static Addr IR_ptr_constval(IRConst* c)
{
#if VG_WORDSIZE == 8
  return c->Ico.U64;
#else
  return c->Ico.U32;
#endif
}

static void IR_ptr_const_set(IRConst* c, uintptr_t v)
{
#if VG_WORDSIZE == 8
  c->Ico.U64 = v;
#else
  c->Ico.U32 = v;
#endif
}

static IRConst* IR_const_PTR(uint32_t v)
{
#if VG_WORDSIZE == 8
  return IRConst_U64(v);
#else
  return IRConst_U32(v);
#endif
}

static void* align_to_pointer(void* p)
{
  return (void*)(((uintptr_t)p + sizeof(void*) - 1)&~(sizeof(void*) - 1));
}

static Int align_size_to_pointer(Int len)
{
  return (len + sizeof(void*) - 1)&~(sizeof(void*) - 1);
}

/** Terribly hokey! Debugging only. */
static void ch_pause(void)
{
  volatile int x = 0;
  uint64_t i;
  for (i = 0; i < 2000000000L; ++i) {
    ++x;
  }
}

static void try_exec(Char* path, int len, Char* file, Char** argv)
{
  char buf[1024];
  if (len + VG_(strlen)(file) + 2 > sizeof(buf))
    return;
  VG_(strncpy)(buf, path, len);
  buf[len] = '/';
  VG_(strcpy)(buf + len + 1, file);
  VG_(execv)(buf, argv);
}

static void my_execvp(Char* file, Char** argv)
{
  HChar* path = VG_(getenv)("PATH");
  if (!path) {
    VG_(execv)(file, argv);
    return;
  }

  for (;;) {
    HChar* colon = VG_(strchr)(path, ':');
    if (!colon) {
      try_exec(path, VG_(strlen)(path), file, argv);
      return;
    }
    try_exec(path, colon - path, file, argv);
    path = colon + 1;
  }
}

static void spawn_indexer_process(void)
{
  Int to_indexer[2];
  Int from_indexer[2];
  Int pid;
  Int res = VG_(pipe)(to_indexer);
  if (res < 0)
    VG_(tool_panic)("Cannot create to-indexer pipe!");

  res = VG_(pipe)(from_indexer);
  if (res < 0)
    VG_(tool_panic)("Cannot create from-indexer pipe!");

  pid = VG_(fork)();
  if (pid < 0)
    VG_(tool_panic)("Couldn't fork!");

  if (!pid) {
    Char* args[] = { "chronicle-indexer", NULL };

    /* child */
    VG_(dup2)(to_indexer[0], 0);
    VG_(dup2)(from_indexer[1], 1);
    VG_(close)(to_indexer[0]);
    VG_(close)(to_indexer[1]);
    VG_(close)(from_indexer[0]);
    VG_(close)(from_indexer[1]);

    my_execvp(args[0], args);

    /* BAH, execv failed */
    VG_(tool_panic)("Couldn't exec chronicle-indexer!");
  }

  /* parent */
  VG_(close)(to_indexer[0]);
  VG_(close)(from_indexer[1]);
  write_to_indexer_fd = to_indexer[1];
  read_from_indexer_fd = from_indexer[0];

  /* Maybe wait so someone can attach a debugger... */
  if (0) ch_pause();
}

static void read_from_indexer(void* data, Int len)
{
  Int r;

  tl_assert2(tracing_enabled,
             "Trying to read from indexer with trace disabled");

  r = VG_(read)(read_from_indexer_fd, data, len);
  if (r != len)
    VG_(tool_panic)("Cannot read from indexer pipe!");
}

static void write_to_indexer(void* data, Int len)
{
  Int r;

  tl_assert2(tracing_enabled,
             "Trying to read from indexer with trace disabled");

  r = VG_(write)(write_to_indexer_fd, data, len);
  if (r != len)
    VG_(tool_panic)("Cannot write to indexer pipe!");
}

static void ensure_buffer_size(void** buf, Int* size, Int required_size)
{
  if (*size < required_size) {
    Int new_size = *size*2;
    if (new_size < required_size) {
      new_size = required_size;
    }
    *buf = VG_(realloc)(*buf, new_size);
    if (!*buf)
      VG_(tool_panic)("Memory allocation failed!");
  }
}

static void map_buffers(void)
{
  Char buf[1024];
  Int i = 0;
  Int fd;
  SysRes r;
  while (i < sizeof(buf)) {
    read_from_indexer(&buf[i], 1);
    if (!buf[i])
      break;
    ++i;
  }
  buf[sizeof(buf) - 1] = 0;

  r = VG_(open)(buf, VKI_O_RDWR, 0);
  if (r.isError)
    VG_(tool_panic)("Cannot open trace buffer file!");
  fd = (Int)r.res;

  /* remove the file now, everyone has it open */
  VG_(unlink)(buf);

  trace_buffer_size = VG_(lseek)(fd, 0, VKI_SEEK_END);
  if (trace_buffer_size < 0)
    VG_(tool_panic)("Cannot get size of trace buffer file!");

  trace_buffer_base =
    VG_(am_mmap_file)(trace_buffer_size, VKI_PROT_READ|VKI_PROT_WRITE, True, fd, 0);
  if (!trace_buffer_base)
    VG_(tool_panic)("Cannot mmap trace buffer file!");
}

static int got_buffer;

static void acquire_buffer(void)
{
  tl_assert2(!got_buffer, "Already got a buffer!");
  read_from_indexer(&trace_buffer_base->offsets, sizeof(trace_buffer_base->offsets));
  trace_buffer = (Char*)trace_buffer_base + trace_buffer_base->offsets.buffer_start;
  /* Reserve enough space for a terminating record */
  trace_buffer_end = (Char*)trace_buffer + trace_buffer_base->offsets.buffer_length - 
    sizeof(CH_RecordHeader);
  got_buffer = 1;
}

static void release_buffer(void)
{
  CH_RecordHeader* r = trace_buffer;
  if (!r)
    return;

  tl_assert2(got_buffer, "Released buffer?");
  r->code_index = CH_END_BUFFER;
  r->length = sizeof(CH_RecordHeader);

  trace_buffer = trace_buffer_end = 0;
  /* VG_(msync)((Char*)trace_buffer_base + trace_buffer_offsets[0],
             trace_buffer_offsets[1], VKI_MS_SYNC|VKI_MS_INVALIDATE); */
  write_to_indexer(&trace_buffer_base->offsets, sizeof(trace_buffer_base->offsets));
  got_buffer = 0;
}

static CH_RecordHeader* prepare_record(uint32_t code_index, uint32_t length)
{
  CH_RecordHeader* r;

  tl_assert2((length&(sizeof(void*)-1))==0,
             "Unaligned record length %d (index %d)", length, code_index);

  if (!tracing_enabled)
    return trace_buffer;

  if ((Char*)trace_buffer_end - (Char*)trace_buffer < length) {
    release_buffer();
    acquire_buffer();
  }

  r = trace_buffer;
  trace_buffer = (Char*)trace_buffer + length;

  /* save pointer to current record so that the indexer can pick it up if we crash or
     unexpectedly exit */
  trace_buffer_base->last_record = (Char*)r - (Char*)trace_buffer_base;

  r->code_index = code_index;
  r->length = length;
  return r;
}

static void send_flags(void)
{
  CH_Record_Init* r = (CH_Record_Init*)
    prepare_record(CH_INIT, align_size_to_pointer(sizeof(CH_Record_Init)));
  r->flags = control_flags;
}

/**
 * To avoid having to copy the contents of all executable files into our
 * log, we identify some memory-mapped files as "static" and then assume
 * they'll be available, unchanged, at debug time. We hope that
 * user-executable or user-non-writable files are static.
 */
static Bool is_static_file(CH_Record_SetAddrMap* r, HChar* filename)
{
  struct vki_stat buf;
  SysRes res;

  if (!r->is_file)
    return False;

  res = VG_(stat)((Char*)filename, &buf);
  if (res.isError)
    return False;

  /* check that the file we just stat'ed is the file that's actually been
   * mmapped */
  if (buf.st_dev != r->device || buf.st_ino != r->inode)
    return False;

  if (buf.st_mode & 0700) {
    /* User executable, assume it's static */
    return True;
  }

  if (!(buf.st_mode & 0600)) {
    /* User NONwritable, assume it's static */
    return True;
  }

  return False;
}

static void do_bulk_write(Addr addr, SizeT len)
{
  if (!tracing_enabled)
    return;

  while (len > 0) {
    CH_Record_BulkWrite* r;
    Int available = (Char*)trace_buffer_end - (Char*)trace_buffer -
      sizeof(CH_Record_BulkWrite);
    SizeT amount;
    if (available < 1000) {
      release_buffer();
      acquire_buffer();
      continue;
    }
    
    if ((UInt)available < len) {
      amount = available;
    } else {
      amount = len;
    }

    r = (CH_Record_BulkWrite*)
      prepare_record(CH_BULK_WRITE,
                     sizeof(CH_Record_BulkWrite) +
                     align_size_to_pointer(amount));
    r->address = addr;
    r->length = (uint32_t)amount;
    VG_(memcpy)(r + 1, (void*)addr, amount);
    addr += amount;
    len -= amount;
  }
}

static Bool in_map_setup;

static void address_space_changed(NSegment* seg,
                                  Addr offset,
                                  Addr length,
                                  Bool contents_changed,
                                  Bool is_V_to_C_transfer,
                                  void *closure)
{
  Int len = sizeof(CH_Record_SetAddrMap);
  CH_Record_SetAddrMap* r;
  HChar* filename;

  /* ignore valgrind mappings */
  if (seg->kind == SkAnonV ||
      seg->kind == SkFileV)
    return;

  filename = VG_(am_get_filename)(seg);
  if (filename != NULL) {
    len += VG_(strlen)(filename) + 1;
  }
  r = (CH_Record_SetAddrMap*)
    prepare_record(CH_SET_ADDR_MAP, align_size_to_pointer(len));

  r->address = seg->start + offset;
  r->length = length;
  r->is_mapped = seg->kind != SkFree && seg->kind != SkResvn;
  r->is_read = seg->hasR;
  r->is_write = seg->hasW;
  r->is_execute = seg->hasX;
  r->is_file = seg->kind == SkFileC;
  r->suppress_debug_info = is_V_to_C_transfer;
  r->device = seg->dev;
  r->inode = seg->ino;
  r->offset = seg->offset + offset;
  r->file_name_follows = filename != NULL;
  if (r->file_name_follows) {
    VG_(strcpy)((char*)(r + 1), filename);
  }
  r->contents_unchanged = !contents_changed;
  r->contents_set_zero = False;
  r->contents_will_follow = False;
  r->contents_from_file = False;
  if (contents_changed && r->is_mapped) {
    /* when we first read the segment table at startup, a /dev/zero mapping
       doesn't necessarily mean that the contents are zero. They might have
       been filled in by the kernel (or valgrind mimicing the kernel). */
    if (r->device == 0 && !in_map_setup) {
      r->contents_set_zero = True;
    } else if (is_static_file(r, filename)) {
      r->contents_from_file = True;
    } else if (r->is_read) {
      r->contents_will_follow = True;
      do_bulk_write(r->address, r->length);
    }
  }
}

static void start_watching_maps(void)
{
  Int max_starts = 0;
  Addr* starts_buf = NULL;
  Int n_starts;
  Int i;

  for (;;) {
    n_starts = VG_(am_get_segment_starts)(starts_buf, max_starts);
    if (n_starts >= 0)
      break;
    max_starts = -n_starts;
    starts_buf = VG_(realloc)(starts_buf, max_starts*sizeof(Addr));
  }

  in_map_setup = True;  
  for (i = 0; i < n_starts; ++i) {
    NSegment* seg = (NSegment*)VG_(am_find_nsegment)(starts_buf[i]);

    address_space_changed(seg, 0, seg->end + 1 - seg->start, True, False,
                          NULL);
  }
  in_map_setup = False;
  VG_(am_set_change_hook)(address_space_changed, NULL);
  
  VG_(free)(starts_buf);
}

static void disable_tracing(void)
{
  static CH_TraceHeader dummy;

  tracing_enabled = False;

  /* Free up resources and protect any ongoing tracing
     using this channel in a parent process */
  VG_(close)(write_to_indexer_fd);
  VG_(close)(read_from_indexer_fd);
  /* VG_(munmap)(trace_buffer_base, trace_buffer_size); */

  /* Create our own scratch buffer with the same size.
     Existing instrumented code will just dump its log
     here to be ignored */
  trace_buffer_base = &dummy;
  trace_buffer = VG_(malloc)(trace_buffer_size);
  trace_buffer_end = (Char*)trace_buffer_base + trace_buffer_size;
}

static void ch_atfork_child(ThreadId t)
{
  /* we don't handle fork well yet (it's conceptually difficult).
     For now we just disconnect the child and let it run without
     being traced. */
  disable_tracing();
}

static void ch_post_clo_init(void)
{
  spawn_indexer_process();
  map_buffers();
  send_flags();
  start_watching_maps();
  VG_(atfork_child)(ch_atfork_child);
}

static void emit_reset_state(VexGuestState* state, ThreadId tid)
{
  CH_Record_ResetState* r = (CH_Record_ResetState*)
    prepare_record(CH_RESET_STATE, sizeof(CH_Record_ResetState));
  CH_Context* context = &r->context;

#if defined(VGA_x86)
  VG_(memcpy)(context->regs_GP, &state->guest_EAX, 8*sizeof(state->guest_EAX));
  VG_(memcpy)(context->regs_SSE, &state->guest_XMM0, 8*sizeof(CH_X86_SSEReg));
  VG_(memcpy)(context->regs_FP, state->guest_FPREG, sizeof(state->guest_FPREG));
  context->FP_top = state->guest_FTOP;
  /* XXX what about FP register tags? */
#elif defined(VGA_amd64)
  VG_(memcpy)(context->regs_GP, &state->guest_RAX, 16*sizeof(state->guest_RAX));
  VG_(memcpy)(context->regs_SSE, &state->guest_XMM0, 16*sizeof(CH_X86_SSEReg));
  VG_(memcpy)(context->regs_FP, state->guest_FPREG, sizeof(state->guest_FPREG));
  context->FP_top = state->guest_FTOP;
  /* XXX what about FP register tags? */
#else
#error Unknown architecture
#endif
  r->SP_max = SP_max;
  r->thread_ID = (uint32_t)tid;
  
  /* reset SP_max to the initial SP */
  SP_max = context->regs_GP[CH_X86_SP];
}

/* This is performance critical, since it gets executed
   at the start of every superblock! */
static void* prepare_code_record(void* guest_state,
                                 uintptr_t code_index, uintptr_t size,
                                 uintptr_t SP_max_offset)
{
  CH_Record_Exec* r = trace_buffer;
  Char* next_record = (Char*)r + size;
  ThreadId tid = VG_(get_running_tid)();
  uintptr_t new_SP_max;

  if (!tracing_enabled) {
    /* just return the initial buffer */
    return r;
  }

  if ((void*)next_record >= trace_buffer_end) {
    release_buffer();
    acquire_buffer();

    r = trace_buffer;
    next_record = (Char*)r + size;
  }

  if (state_reset_countdown <= 0 || tid != last_thread) {
    emit_reset_state(guest_state, tid);
    state_reset_countdown = state_reset_period;
    last_thread = tid;
    r = trace_buffer;
    next_record = (Char*)r + size;

    if ((void*)next_record >= trace_buffer_end) {
      release_buffer();
      acquire_buffer();
      
      r = trace_buffer;
      next_record = (Char*)r + size;
    }
  }

  /* save pointer to current record so that the indexer can pick it up if we crash or
     unexpectedly exit */
  trace_buffer_base->last_record = (Char*)r - (Char*)trace_buffer_base;

  new_SP_max = ((VexGuestState*)guest_state)->VexGuestState_SP + SP_max_offset;
  if (new_SP_max > SP_max) {
    SP_max = new_SP_max;
  }

  --state_reset_countdown;

  trace_buffer = next_record;
  r->header.code_index = code_index;
  r->header.length = size;
  r->instructions_retired = 0;
  return r;
}

static void update_max_SP(void* guest_state,
                           uintptr_t SP_max_offset)
{
  uintptr_t new_SP_max =
    ((VexGuestState*)guest_state)->VexGuestState_SP + SP_max_offset;
  if (new_SP_max > SP_max) {
    SP_max = new_SP_max;
  }
}

/* just like prepare_code_record, but we zero out the record
   memory. Use this when our zero-out code at the end of the
   block might not be reached. */
static void* prepare_code_record_clean(void* guest_state,
                                      uintptr_t code_index, uintptr_t size,
                                      uintptr_t SP_max_offset)
{
  uint8_t* r = prepare_code_record(guest_state, code_index, size, SP_max_offset);
  /* now we zero out everything after the header */
  uintptr_t* mem = (uintptr_t*)(r + align_size_to_pointer(sizeof(CH_Record_Exec)));
  uintptr_t* end = (uintptr_t*)(r + size);

  while (mem < end) {
    *mem = 0;
    mem++;
  }
  return r;
}
/* End helpers */

static uint32_t next_code_index = CH_MAX_BUILTIN_RECORDS + 1;

/* all this stuff gets reset for every BB */

static CH_BunchedEffect* bunched_effects;
static Int bunched_effects_size;
static CH_RegEffect* reg_effects;
static Int reg_effects_size;

typedef struct {
  IRConst* offsets[CH_EFFECT_ATOMS];
} CH_BunchedTraceDataOffsets;
static CH_BunchedTraceDataOffsets* bunched_effech_trace_data_offsets;
static Int bunched_effech_trace_data_offsets_size;
static IRConst** reg_effech_trace_data_offsets;
static Int reg_effech_trace_data_offsets_size;

static Int bunched_effech_for_map[CH_MAX_BUILTIN_MAP+1];
static IRTemp dynamic_temps_for_map[CH_MAX_BUILTIN_MAP+1];
static Int bunched_effech_count;
static Int reg_effech_count;

typedef struct {
  IRTemp   temp;
  uint8_t  log2_bytes_available;
  intptr_t offset;
} AvailableExpression;
static AvailableExpression reg_available_expressions[CH_NUM_REGS];

typedef struct {
  uint32_t subchunk_offset[CH_PTR_LOG2_BYTES];
  uint32_t next_pointer_offset;
} CH_TraceRecordAllocation;

static void init_trace_record_allocation(CH_TraceRecordAllocation* allocation,
                                         uint32_t initial_offset)
{
  int i;
  for (i = 0; i < CH_PTR_LOG2_BYTES; ++i) {
    allocation->subchunk_offset[i] = 0;
  }
  allocation->next_pointer_offset = initial_offset;
}

static uint32_t trace_record_allocate(CH_TraceRecordAllocation* allocation,
                                      uint8_t size_log2_bytes)
{
  uint32_t r;
  if (size_log2_bytes < CH_PTR_LOG2_BYTES) {
    r = allocation->subchunk_offset[size_log2_bytes];
    if (r) {
      allocation->subchunk_offset[size_log2_bytes] = 0;
      return r;
    }
    r = trace_record_allocate(allocation, size_log2_bytes + 1);
    allocation->subchunk_offset[size_log2_bytes] =
      r + (1 << size_log2_bytes);
    return r;
  }

  r = allocation->next_pointer_offset;
  allocation->next_pointer_offset += 1 << size_log2_bytes;
  return r;
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

static void add_reg_effect(CH_RegEffect* effect, IRConst* trace_data_offset1,
                           IRConst* trace_data_offset2)
{
  Int i = reg_effech_count;
  reg_effech_count = i + 1;

  ensure_buffer_size((void**)&reg_effects, &reg_effects_size,
                     sizeof(CH_RegEffect)*(i + 1));
  reg_effects[i] = *effect;

  ensure_buffer_size((void**)&reg_effech_trace_data_offsets,
                     &reg_effech_trace_data_offsets_size,
                     sizeof(IRConst*)*(i + 1)*2);
  reg_effech_trace_data_offsets[i*2] = trace_data_offset1;
  reg_effech_trace_data_offsets[i*2 + 1] = trace_data_offset2;

  if (effect->type == CH_EFFECT_DYNREG_WRITE) {
    for (i = 0; i < CH_NUM_REGS; ++i) {
      reg_available_expressions[i].temp = IRTemp_INVALID;
    }
  } else if (effect->type != CH_EFFECT_DYNREG_READ
             && effect->type != CH_EFFECT_REG_READ) {
    reg_available_expressions[effect->reg].temp = IRTemp_INVALID;
  }
}

static CH_BunchedEffect* allocate_bunched_effect(uint8_t map,
                                                 uint8_t instr_index,
                                                 uint8_t length,
                                                 uintptr_t static_offset,
                                                 Bool has_dynamic_offset,
                                                 Bool uses_dynamic_offset)
{
  CH_BunchedEffect* e;
  Int i = bunched_effech_count;
  int j;

  bunched_effech_count = i + 1;
  ensure_buffer_size((void**)&bunched_effects, &bunched_effects_size,
                     sizeof(CH_BunchedEffect)*(i + 1));
  ensure_buffer_size((void**)&bunched_effech_trace_data_offsets,
                     &bunched_effech_trace_data_offsets_size,
                     sizeof(CH_BunchedTraceDataOffsets)*(i + 1));

  e = &bunched_effects[i];
  tl_assert2(length <= 15, "Overlong effect");
  e->static_offset = static_offset;
  e->map = map;
  e->has_data = map == CH_MAP_MEM_WRITE;
  e->has_dynamic_offset = has_dynamic_offset;
  e->uses_dynamic_offset = uses_dynamic_offset;
  e->first_instruction_index = e->last_instruction_index = instr_index;
  e->length = length;
  e->atoms.atoms[0].instruction_index = 0;
  e->atoms.atoms[0].length_increment = length;
  for (j = 1; j < CH_EFFECT_ATOMS; ++j) {
    e->atoms.atoms[j].instruction_index = 0;
    e->atoms.atoms[j].length_increment = 0;
  }
  bunched_effech_for_map[map] = i;

  for (j = 0; j < CH_EFFECT_ATOMS; ++j) {
    bunched_effech_trace_data_offsets[i].offsets[j] = NULL;
  }
  return e;
}

static void init_bunched_effects(void)
{
  int i;
  bunched_effech_count = 0;
  reg_effech_count = 0;
  for (i = 0; i <= CH_MAX_BUILTIN_MAP; ++i) {
    dynamic_temps_for_map[i] = IRTemp_INVALID;
    bunched_effech_for_map[i] = -1;
  }
}

static void init_available_expressions(void)
{
  int i;
  for (i = 0; i < CH_NUM_REGS; ++i) {
    reg_available_expressions[i].temp = IRTemp_INVALID;
  }
}

static void add_instruction_effect(uint8_t instruction_index,
                                   uintptr_t instruction_address,
                                   uint8_t length)
{
  Int e_index = bunched_effech_for_map[CH_MAP_INSTR_EXEC];
  CH_BunchedEffect* e = e_index < 0 ? NULL : &bunched_effects[e_index];
  int i;
  tl_assert2(length > 0 && length <= 15, "bad instruction length %d",
             length);
  tl_assert2(!e || instruction_index >= e->last_instruction_index,
             "Instructions out of order: %p, %d, %d", e,
             instruction_index, e->last_instruction_index);
  if (e && instruction_index <= (uint32_t)e->first_instruction_index + 15
      && e->static_offset + e->length == instruction_address) {
    tl_assert2(e->atoms.atoms[CH_EFFECT_ATOMS - 1].length_increment == 0,
               "Couldn't find hole");
    /* pack this instruction into the current bunch */
    for (i = 1; i < CH_EFFECT_ATOMS; ++i) {
      if (e->atoms.atoms[i].length_increment == 0)
        break;
    }
    e->atoms.atoms[i].length_increment = length;
    e->atoms.atoms[i].instruction_index = instruction_index -
      e->first_instruction_index;
    e->last_instruction_index = instruction_index;
    e->length += length;
    if (e->atoms.atoms[CH_EFFECT_ATOMS - 1].length_increment != 0) {
      /* this bunch is now full */
      bunched_effech_for_map[CH_MAP_INSTR_EXEC] = -1;
    }
    return;
  }

  allocate_bunched_effect(CH_MAP_INSTR_EXEC, instruction_index, length,
                          instruction_address, False, False);
}

/*
 * Valgrind can sometimes churn through a lot of retranslation of the same
 * instructions. We normally allocate a new code_index for each new
 * translation, but that's wasteful if the same code is being retranslated.
 * Allocating new code_indexes could be a performance problem and could
 * even result in us running out of code_indexes since they're only 32bit.
 * So we keep a record of the instruction sequences that have been translated
 * and detect retranslations and reuse the code_index for the previous
 * translation of the same instruction sequence.
 */

typedef struct {
  uint32_t code_index;
  uint16_t data_len;
  /* uint8_t data follows */
} InstrHashEntry;
static InstrHashEntry** instr_hash_table;
static Int instr_hash_table_size;

static uint8_t* instr_string_buffer;
static Int instr_string_buffer_size;
static Int instr_string_buffer_len;

static uint32_t hash_addr(uintptr_t addr)
{
  return (addr ^ (addr >> 8)) & (instr_hash_table_size - 1);
}

static int instruction_map_hash_lookup(uintptr_t addr, void* istring,
                                       uint16_t istring_len, uint32_t* code_index)
{
  InstrHashEntry* p;
  Int new_strbuf_len;
  uint32_t h = hash_addr(addr);
  if (instr_hash_table_size > 0) {
    while ((p = instr_hash_table[h])) {
      if (p->data_len == istring_len &&
          VG_(memcmp)(istring, (uint8_t*)p + 6, istring_len) == 0) {
        *code_index = p->code_index;
        return 0;
      }
      ++h;
      if (h >= instr_hash_table_size) {
        h = 0;
      }
    }
  }

  *code_index = next_code_index;
  ++next_code_index;
  if (next_code_index < CH_MAX_BUILTIN_RECORDS)
    VG_(tool_panic)("Code index overflow!");
  return 1;

  new_strbuf_len = align_size_to_pointer(instr_string_buffer_len + istring_len + 6);
  ensure_buffer_size((void**)&instr_string_buffer, &instr_string_buffer_size,
                     new_strbuf_len);
  p = (InstrHashEntry*)(instr_string_buffer + instr_string_buffer_len);
  p->code_index = *code_index;
  p->data_len = istring_len;
  VG_(memcpy)((uint8_t*)p + 6, istring, istring_len);
  instr_string_buffer_len = new_strbuf_len;

  if (next_code_index*3 > instr_hash_table_size) {
    InstrHashEntry** new_table;
    Int old_size = instr_hash_table_size;
    int i;

    instr_hash_table_size *= 2;
    if (next_code_index*3 > instr_hash_table_size) {
      instr_hash_table_size = next_code_index*3;
    }
    new_table = VG_(malloc)(sizeof(InstrHashEntry*)*instr_hash_table_size);
    VG_(memset)(new_table, 0, sizeof(InstrHashEntry*)*instr_hash_table_size);
    for (i = 0; i < old_size; ++i) {
      InstrHashEntry* e = instr_hash_table[i];
      if (e) {
        uintptr_t offset;
        int j;

        VG_(memcpy)(&offset, (uint8_t*)e + 6, sizeof(uintptr_t));
        j = hash_addr(offset);
        while (new_table[j]) {
          ++j;
          if (j >= instr_hash_table_size) {
            j = 0;
          }
        }
        new_table[j] = e;
      }
    }

    VG_(free)(instr_hash_table);
    instr_hash_table = new_table;
  }

  h = hash_addr(addr);
  while (instr_hash_table[h]) {
    ++h;
    if (h >= instr_hash_table_size) {
      h = 0;
    }
  }
  instr_hash_table[h] = p;
  return 1;
}

/**
 * Return true if this is a code sequence we haven't seen before.
 */
static int allocate_code_index(uint32_t* code_index)
{
  uint32_t i;
  uint8_t buf[255*(15 + sizeof(uintptr_t))];
  uint16_t len = 0;
  uintptr_t first_offset = 0;

  /* build an instruction string for hashing/comparison. It's basically a list
     of all the instructions in the block: their addresses and code bytes. */
  for (i = 0; i < bunched_effech_count; ++i) {
    uint8_t bunch_len = bunched_effects[i].length;
    uintptr_t offset = bunched_effects[i].static_offset;
    if (bunched_effects[i].map != CH_MAP_INSTR_EXEC)
      continue;
    if (first_offset == 0) {
      first_offset = offset;
    }
    VG_(memcpy)(&buf[len], &offset, sizeof(uintptr_t));
    len += sizeof(uintptr_t);
    buf[len] = bunch_len;
    len++;
    /* put the actual instructions in the string so we can detect
       if the code changed between translations. This reads guest
       memory directly! */
    VG_(memcpy)(&buf[len], (void*)offset, bunch_len);
    len += bunch_len;
  }

  return instruction_map_hash_lookup(first_offset, buf, len, code_index);
}

/* Returns true if we need the value of the address_temp to be stored in
   the log */
static Bool add_mem_effect(uint8_t map, uint8_t instruction_index,
                           IRTemp address_temp, intptr_t address_offset,
                           uint8_t length, IRConst* trace_data_offset)
{
  Int e_index = bunched_effech_for_map[map];
  CH_BunchedEffect* e = e_index < 0 ? NULL : &bunched_effects[e_index];
  int i = 0;
  Bool has_dynamic_offset;

  tl_assert2(length > 0 && length <= 16, "bad length %d", length);
  tl_assert2(!e || instruction_index >= e->last_instruction_index,
             "Instructions out of order: %p, %d, %d", e,
             instruction_index, e->last_instruction_index);
  tl_assert2(map == CH_MAP_MEM_WRITE || !trace_data_offset,
             "Unexpected trace data");
  if (e && instruction_index <= (uint32_t)e->first_instruction_index + 15
      && dynamic_temps_for_map[map] == address_temp && length <= 15) {
    Bool found = 0;
    CH_BunchedTraceDataOffsets* offs =
      &bunched_effech_trace_data_offsets[e - bunched_effects];
    tl_assert2(e->atoms.atoms[CH_EFFECT_ATOMS - 1].length_increment == 0,
               "Couldn't find hole");
    /* consider adding to the end of the bunch */
    if (e->static_offset + e->length == address_offset) {
      for (i = 1; i < CH_EFFECT_ATOMS; ++i) {
        if (e->atoms.atoms[i].length_increment == 0)
          break;
      }
      found = 1;
    }

    /* consider adding to the beginning of the bunch */
    if (e->static_offset == address_offset + length) {
      /* make a hole at the beginning */
      for (i = CH_EFFECT_ATOMS - 1; i > 0; --i) {
        e->atoms.atoms[i] = e->atoms.atoms[i - 1];
        offs->offsets[i] = offs->offsets[i - 1];
      }
      i = 0;
      found = 1;
      e->static_offset -= length;
    }

    if (found) {
      e->atoms.atoms[i].length_increment = length;
      e->atoms.atoms[i].instruction_index = instruction_index -
        e->first_instruction_index;
      offs->offsets[i] = trace_data_offset;
      e->last_instruction_index = instruction_index;
      e->length += length;
      if (e->atoms.atoms[CH_EFFECT_ATOMS - 1].length_increment != 0) {
        /* this bunch is now full */
        bunched_effech_for_map[map] = -1;
      }
      return False;
    }
  }

  if (address_temp == IRTemp_INVALID ||
      dynamic_temps_for_map[map] == address_temp) {
    has_dynamic_offset = False;
  } else {
    has_dynamic_offset = True;
    dynamic_temps_for_map[map] = address_temp;
  }

  if (length <= 15) {
    e = allocate_bunched_effect(map, instruction_index, length,
                                address_offset,
                                has_dynamic_offset,
                                address_temp != IRTemp_INVALID);
  } else {
    /* handle length == 16 case by breaking into two 8-byte parts */
    e = allocate_bunched_effect(map, instruction_index, 8,
                                address_offset,
                                has_dynamic_offset,
                                address_temp != IRTemp_INVALID);
    e->atoms.atoms[1].instruction_index = instruction_index;
    e->atoms.atoms[1].length_increment = 8;
    /* indicate that we have no offset to store here but the length
       bump should still happen */
    bunched_effech_trace_data_offsets[e - bunched_effects].offsets[1] =
      IR_const_INVALID;
  }
  bunched_effech_trace_data_offsets[e - bunched_effects].offsets[0] =
    trace_data_offset;
  return has_dynamic_offset;
}

static IRConst* add_trace_store(IRSB* bb, IRTemp tmp_trace_rec_ptr,
                                uint32_t offset, IRExpr* value)
{
  IRConst* c = IR_const_PTR(offset);
  IRExpr* offset_expr = IRExpr_Const(c);
  IRTemp tmp = newIRTemp(bb->tyenv, IR_ptr_type);
  IRExpr* taddr = IRExpr_Binop(IR_ptr_add, IRExpr_RdTmp(tmp_trace_rec_ptr),
                               offset_expr);
  addStmtToIRSB(bb, IRStmt_WrTmp(tmp, taddr));
  addStmtToIRSB(bb, IRStmt_Store(IR_end, IRExpr_RdTmp(tmp), value));
  return c;
}

static void add_trace_store_flatten(IRSB* bb, IRTemp tmp_trace_rec_ptr,
                                    uint32_t offset, IRExpr* value)
{
  IRTemp tmp = newIRTemp(bb->tyenv, typeOfIRExpr(bb->tyenv, value));
  addStmtToIRSB(bb, IRStmt_WrTmp(tmp, value));
  add_trace_store(bb, tmp_trace_rec_ptr, offset, IRExpr_RdTmp(tmp));
}

static void add_retirement_store(IRSB* bb, IRTemp tmp_retired_instructions_ptr, 
                                 uint8_t instr)
{
  IRExpr* e = IRExpr_Const(IRConst_U8(instr));
  addStmtToIRSB(bb, IRStmt_Store(IR_end,
                                 IRExpr_RdTmp(tmp_retired_instructions_ptr),
                                 e));
}

static Int allocate_bunch_effech_trace_offsets(Int offset)
{
  /* Allocate storage for effect data; each bunch's data must be
     a contiguous block */
  int i;

  tl_assert2(offset == align_size_to_pointer(offset),
             "Unaligned offset on entry %x\n", offset);
  for (i = 0; i < bunched_effech_count; ++i) {
    CH_BunchedTraceDataOffsets* offs = &bunched_effech_trace_data_offsets[i];
    int j;
    for (j = 0; j < CH_EFFECT_ATOMS; ++j) {
      if (offs->offsets[j]) {
        tl_assert2(offset < 0x10000, "trace record overflow");
        if (offs->offsets[j] != IR_const_INVALID) {
          IR_ptr_const_set(offs->offsets[j], offset);
        }
        offset += bunched_effects[i].atoms.atoms[j].length_increment;
      }
    }

    offset = align_size_to_pointer(offset);
  }

  return offset;
}

static Int allocate_reg_effech_trace_offsets(IRSB* bb, Int offset, 
                                             IRTemp tmp_trace_rec_ptr)
{
  CH_TraceRecordAllocation reg_allocation;
  int i;

  tl_assert2(offset == align_size_to_pointer(offset),
             "Unaligned offset on entry %x\n", offset);
  init_trace_record_allocation(&reg_allocation, offset);
  /* Allocate storage for regeffect data */
  for (i = 0; i < reg_effech_count; ++i) {
    if (reg_effech_trace_data_offsets[i*2]) {
      uint32_t off = trace_record_allocate(&reg_allocation,
                                           reg_effects[i].bytes_pow2);
      tl_assert2(off < 0x10000, "trace record overflow");
      IR_ptr_const_set(reg_effech_trace_data_offsets[i*2], off);
    }
    if (reg_effech_trace_data_offsets[i*2 + 1]) {
      uint32_t off = trace_record_allocate(&reg_allocation, 0);
      tl_assert2(off < 0x10000, "trace record overflow");
      IR_ptr_const_set(reg_effech_trace_data_offsets[i*2 + 1], off);
    }
  }

  if (tmp_trace_rec_ptr != IRTemp_INVALID) {
    /* add instructions to zero out any holes */
    for (i = 0; i < CH_PTR_LOG2_BYTES; ++i) {
      if (reg_allocation.subchunk_offset[i]) {
        IRConst* c;
        switch (i) {
        case 0: c = IRConst_U8(0); break;
        case 1: c = IRConst_U16(0); break;
        case 2: c = IRConst_U32(0); break;
        default:
          tl_assert2(0, "strange architecture with size %d\n", i);
        }
        add_trace_store(bb, tmp_trace_rec_ptr, reg_allocation.subchunk_offset[i],
                        IRExpr_Const(c));
      }
    }
  }

  return reg_allocation.next_pointer_offset;
}

static Bool widen_const(IRConst* c, intptr_t* val)
{
  switch (c->tag) {
  case Ico_U1:   *val = c->Ico.U1; return True;
  case Ico_U8:   *val = c->Ico.U8; return True;
  case Ico_U16:  *val = c->Ico.U16; return True;
  case Ico_U32:  *val = c->Ico.U32; return True;
#if VG_WORDSIZE == 8
  case Ico_U64:  *val = c->Ico.U64; return True;
#endif
  default:
    return False;
  }
}

/* Determine whether 'expr' can be boiled down to a tmp plus an offset,
   chasing back to the earliest tmp for which this is true. Returns True
   if we determine this, in which case the offset is returned in 'offset'
   and the tmp in 'tmp'.

   If 'expr' actually boils down to a constant, then we return True
   and set 'tmp' to IRTemp_INVALID, leaving the constant in 'offset'.
 */
static Bool find_base_temp(IRSB* bb, int i, IRExpr* expr, intptr_t* offset, IRTemp* tmp)
{
  intptr_t off;
  IRTemp last;

  if (expr->tag == Iex_Const) {
    if (widen_const(expr->Iex.Const.con, offset)) {
      *tmp = IRTemp_INVALID;
      return True;
    }
    return False;
  }
  tl_assert2(expr->tag == Iex_RdTmp, "Non-flat expr %d", expr->tag);

  last = expr->Iex.RdTmp.tmp;
  off = 0;
  while (i > 0) {
    --i;
    if (bb->stmts[i]) {
      IRStmt* st = bb->stmts[i];
      if (st->tag == Ist_WrTmp && st->Ist.WrTmp.tmp == last) {
        /* this statement sets the temp we're interested in;
           if it's just another temp plus an offset, start watching
           the referenced temp instead */
        IRExpr* e = st->Ist.WrTmp.data;
        if (e->tag == Iex_RdTmp) {
          last = e->Iex.RdTmp.tmp;
          continue;
        } else if (e->tag == Iex_Binop &&
                   (e->Iex.Binop.op == IR_ptr_add || e->Iex.Binop.op == IR_ptr_sub)) {
          IRExpr* e1 = e->Iex.Binop.arg1;
          IRExpr* e2 = e->Iex.Binop.arg2;
          intptr_t o;
          if (e1->tag == Iex_RdTmp && e2->tag == Iex_Const) {
            if (widen_const(e2->Iex.Const.con, &o)) {
              int scale = e->Iex.Binop.op == IR_ptr_add ? 1 : -1;
              off += scale*o;
              last = e1->Iex.RdTmp.tmp;
              continue;
            }
          } else if (e2->tag == Iex_RdTmp && e1->tag == Iex_Const
                     && e->Iex.Binop.op == IR_ptr_add) {
            if (widen_const(e1->Iex.Const.con, &o)) {
              off += o;
              last = e2->Iex.RdTmp.tmp;
              continue;
            }
          }
        } else if (e->tag == Iex_Const) {
          intptr_t o;
          if (widen_const(e->Iex.Const.con, &o)) {
            *offset = o + off;
            *tmp = IRTemp_INVALID;
            return True;
          }
        }

        *offset = off;
        *tmp = last;
        return True;
      }
    }
  }
  ppIRSB(bb_in_debug);
  tl_assert2(0, "Cannot find definition for temp %d\n", last);
  return False;
}

static uint8_t get_log2_bytes_type(IRType t) {
  switch (t) {
  case Ity_I8: return 0;
  case Ity_I16: return 1;
  case Ity_I32: case Ity_F32: return 2;
  case Ity_I64: case Ity_F64: return 3;
  case Ity_I128: case Ity_V128: return 4;
  default:
    tl_assert2(0, "Unknown type %d!", t);
    return 0;
  }
}

static uint8_t get_log2_bytes(IRSB* bb, IRExpr* expr)
{
  return get_log2_bytes_type(typeOfIRExpr(bb->tyenv, expr));
}

static Bool convert_offset_to_reg(UInt offset, uint8_t* reg,
                                  uint8_t* offset_in_reg)
{
#ifdef CH_X86
#if defined(VGA_amd64)
  Int XMMEnd = CH_OFFSETOF(VexGuestState, guest_FTOP);
#elif defined(VGA_x86)
  Int XMMEnd = CH_OFFSETOF(VexGuestState, guest_CS);
#else
#error Unknown architecture
#endif
  if (offset < CH_OFFSETOF(VexGuestState, guest_CC_OP)) {
    *reg = (offset >> CH_PTR_LOG2_BYTES) + CH_X86_GP_REGS;
    *offset_in_reg = offset & ((1 << CH_PTR_LOG2_BYTES) - 1);
    return True;
  } else if (offset >= CH_OFFSETOF(VexGuestState, guest_FPREG[0])
             && offset < CH_OFFSETOF(VexGuestState, guest_FPTAG[0])) {
    offset -= CH_OFFSETOF(VexGuestState, guest_FPREG[0]);
    *reg = offset/8 + CH_X86_FP_REGS;
    *offset_in_reg = offset%8;
    return True;
  } else if (offset >= CH_OFFSETOF(VexGuestState, guest_XMM0)
             && offset < XMMEnd) {
    offset -= CH_OFFSETOF(VexGuestState, guest_XMM0);
    *reg = offset/16 + CH_X86_SSE_REGS;
    *offset_in_reg = offset%16;
    return True;
  } else if (offset >= CH_OFFSETOF(VexGuestState, guest_FTOP)
             && offset < CH_OFFSETOF(VexGuestState, guest_FTOP) + 4) {
    offset -= CH_OFFSETOF(VexGuestState, guest_FTOP);
    *reg = CH_X86_FPTOP_REG;
    *offset_in_reg = offset;
  }
#else
#error Unknown architecture
#endif
  return False;
}

static void convert_offsets_to_reg_set(int start, int end, uint8_t* reg_set)
{
  int i;

  VG_(memset)(reg_set, 0, 256);
  for (i = start; i < end; ++i) {
    uint8_t reg, offset_in_reg;
    if (convert_offset_to_reg(i, &reg, &offset_in_reg)) {
      reg_set[reg] = 1;
    }
  }
}

static uint8_t get_covering_low_bytes_log2(uint8_t dlog2_bytes, uint8_t reg,
                                           uint8_t offset_in_reg)
{
#if VG_BIGENDIAN
  uint8_t reg_size = 1 << get_reg_size_log2(reg);
  while (offset_in_reg + (1 << dlog2_bytes) < reg_size) {
    ++dlog2_bytes;
  }
#else
  uint8_t limit = offset_in_reg + (1 << dlog2_bytes);
  while ((1 << dlog2_bytes) < limit) {
    ++dlog2_bytes;
  }
#endif
  return dlog2_bytes;
}

static uint8_t get_full_reg_bytes_log2(uint8_t reg)
{
  switch (get_register_type(reg)) {
  case CH_REGTYPE_GP:
    return CH_PTR_LOG2_BYTES;

  case CH_REGTYPE_X86_SSE:
    return 4;

  case CH_REGTYPE_X86_FP:
    return 3;

  case CH_REGTYPE_X86_FPTOP:
    return 0;

  default:
    tl_assert2(0, "Unknown register %d", reg);
    return 0;
  }
}

static IRType get_reg_type(uint8_t reg, uint8_t log2_bytes)
{
  static IRType types[] = { Ity_I8, Ity_I16, Ity_I32, Ity_I64 };

  switch (get_register_type(reg)) {
  case CH_REGTYPE_GP:
    tl_assert2(log2_bytes <= CH_PTR_LOG2_BYTES, "Oversized (%d)", log2_bytes);
    return types[log2_bytes];

  case CH_REGTYPE_X86_SSE:
    switch (log2_bytes) {
    case 2: return Ity_F32;
    case 3: return Ity_F64;
    case 4: return Ity_V128;
    default:
      tl_assert2(0, "Unsupported SSE section size %d", log2_bytes);
      return Ity_INVALID;
    }

  case CH_REGTYPE_X86_FP:
    tl_assert2(log2_bytes == 3, "Unsupported register size %d", log2_bytes);
    return Ity_F64;

  case CH_REGTYPE_X86_FPTOP:
    return Ity_I8;

  default:
    tl_assert2(0, "Unknown register %d", reg);
    return Ity_INVALID;
  }
}

static Int convert_reg_to_offset(uint8_t reg, uint8_t log2_bytes)
{
#ifdef VG_BIGENDIAN
#error Unhandled architecture
#else
  switch (get_register_type(reg)) {
  case CH_REGTYPE_GP:
    return reg*sizeof(void*);
  case CH_REGTYPE_X86_SSE:
    return (reg - CH_X86_SSE_REGS)*16 + CH_OFFSETOF(VexGuestState, guest_XMM0);
  case CH_REGTYPE_X86_FP:
    return (reg - CH_X86_FP_REGS)*8 + CH_OFFSETOF(VexGuestState, guest_FPREG[0]);
  case CH_REGTYPE_X86_FPTOP:
    return CH_OFFSETOF(VexGuestState, guest_FTOP);
  default:
    tl_assert2(0, "Unknown register %d", reg);
    return 0;
  }
#endif
}

static IRExpr* add_reg_read(IRSB* bb, uint8_t reg, uint8_t log2_bytes)
{
  IRType t = get_reg_type(reg, log2_bytes);
  IRTemp tmp = newIRTemp(bb->tyenv, t);
  Int offset = convert_reg_to_offset(reg, log2_bytes);
  addStmtToIRSB(bb, IRStmt_WrTmp(tmp, IRExpr_Get(offset, t)));
  return IRExpr_RdTmp(tmp);
}

static Bool is_x87_IRRegArray(IRRegArray* array)
{
  return array->nElems == 8 && array->elemTy == Ity_F64
    && array->base == CH_OFFSETOF(VexGuestState, guest_FPREG[0]);
}

static Bool is_x87Tag_IRRegArray(IRRegArray* array)
{
  return array->nElems == 8 && array->elemTy == Ity_I8
    && array->base == CH_OFFSETOF(VexGuestState, guest_FPTAG[0]);
}

static IRExpr* add_trace_x87_indirect_reg(IRSB* bb, IRExpr* ix, Int bias)
{
  /* compute (uint8_t)(((ix+bias)&7) + CH_X86_FP_REGS) */
  IRTemp e1 = newIRTemp(bb->tyenv, Ity_I32);
  IRTemp e2 = newIRTemp(bb->tyenv, Ity_I32);
  IRTemp e3 = newIRTemp(bb->tyenv, Ity_I32);
  IRTemp e4 = newIRTemp(bb->tyenv, Ity_I8);
  IRExpr* constBias = IRExpr_Const(IRConst_U32(bias));
  IRExpr* const7 = IRExpr_Const(IRConst_U32(7));
  IRExpr* constRBase = IRExpr_Const(IRConst_U32(CH_X86_FP_REGS));

  addStmtToIRSB(bb, IRStmt_WrTmp(e1, IRExpr_Binop(Iop_Add32, ix, constBias)));
  addStmtToIRSB(bb, IRStmt_WrTmp(e2, IRExpr_Binop(Iop_And32, IRExpr_RdTmp(e1), const7)));
  addStmtToIRSB(bb, IRStmt_WrTmp(e3, IRExpr_Binop(Iop_Add32, IRExpr_RdTmp(e2), constRBase)));
  addStmtToIRSB(bb, IRStmt_WrTmp(e4, IRExpr_Unop(Iop_32to8, IRExpr_RdTmp(e3))));
  return IRExpr_RdTmp(e4);
}

static Bool is_function_entry_addr(Addr address)
{
  Char function_name[2];
  return VG_(get_fnname_if_entry)(address, function_name,
                                  sizeof(function_name));
}

/* returns True if we know *for sure* this is a function entry address,
   otherwise returns False */
static Bool is_function_entry(IRExpr* dst)
{
  IRConst* c;
  
  if (dst->tag != Iex_Const)
    return False;
  c = dst->Iex.Const.con;
  if (c->tag != IR_ptr_const)
    return False;
  return is_function_entry_addr(IR_ptr_constval(c));
}

/* returns True if 'expr' is just the constant 'address'. */
static Bool is_constant_address_expression(IRExpr* expr, Addr address)
{
  IRConst* c;

  if (expr->tag != Iex_Const)
    return False;
  c = expr->Iex.Const.con;
  if (c->tag != IR_ptr_const)
    return False;
  return IR_ptr_constval(c) == address;
}

static void* check_function_target(void* target_addr, void* SP)
{
  void* r = is_function_entry_addr((uintptr_t)target_addr) ? SP : NULL;
  /* VG_(printf)("Checking indirect target: %p, SP=%p, result is %p\n", target_addr, SP, r); */
  return r;
}

static int BB_count = 0;

static IRSB* ch_instrument(VgCallbackClosure* closure, IRSB* bb_in, VexGuestLayout* layout,
                           VexGuestExtents* vge,
                           IRType gWordTy, IRType hWordTy )
{
  IRSB* bb;
  Bool trace_this = False;
  int i;
  Bool recorded_instruction_retirement = True;
  IRTemp tmp_trace_rec_ptr;
  IRTemp tmp_retired_instructions_ptr;
  IRDirty* build_trace_record;
  IRExpr** helper_args;
  IRConst* final_record_length = IR_const_PTR(0);
  IRConst* final_code_index = IR_const_PTR(0);
  uint32_t code_index;
  uint8_t instruction_count = 0;
  uint32_t trace_record_offset = align_size_to_pointer(sizeof(CH_Record_Exec));
  uint32_t reg_log_offset;
  uint8_t* define_code_output;
  uintptr_t bunched_effects_used_size;
  uintptr_t reg_effects_used_size;
  Bool can_early_exit = False;
  CH_Record_DefineCode* r;
  Addr next_instruction_addr = 0;
  int is_new;
  /* the offset to add to SP to get the maximum SP for the code region */
  IRConst* last_SP_max_offset = IR_const_PTR(0);
  /* current SP minus the value of SP at the start of the code region */
  intptr_t current_SP_offset = 0;
  /* record whether we have seen a store of the next-instruction-address,
     which in conjunction with a control transfer indicates we're doing
     some kind of call. */
  Bool stored_next_instruction_addr = False;

  if (!tracing_enabled)
    return bb_in;

  bb_in_debug = bb_in;

  init_bunched_effects();

  if (gWordTy != hWordTy) {
    /* We don't currently support this case. */
    VG_(tool_panic)("host/guest word size mismatch");
  }

  ++BB_count;
  if (BB_count%10000 == 0) {
    VG_(printf)("Basic block count %d\n", BB_count);
  }
  if (0) ppIRSB(bb_in);

  bb           = emptyIRSB();
  bb->tyenv    = deepCopyIRTypeEnv(bb_in->tyenv);
  bb->next     = deepCopyIRExpr(bb_in->next);
  bb->jumpkind = bb_in->jumpkind;

  tmp_trace_rec_ptr = newIRTemp(bb->tyenv, IR_ptr_type);
  tmp_retired_instructions_ptr = newIRTemp(bb->tyenv, IR_ptr_type);

  /* XXX can we improve performance using regparms? */

  helper_args = mkIRExprVec_3(IRExpr_Const(final_code_index),
                              IRExpr_Const(final_record_length),
                              IRExpr_Const(last_SP_max_offset));
  build_trace_record = unsafeIRDirty_1_N(tmp_trace_rec_ptr, 0,
                                         "prepare_code_record",
                                         prepare_code_record, helper_args);
  build_trace_record->needsBBP = True;
  build_trace_record->nFxState = 1;
  build_trace_record->fxState[0].fx = Ifx_Read;
  build_trace_record->fxState[0].offset = 0;
  build_trace_record->fxState[0].size = layout->total_sizeB;

  addStmtToIRSB(bb, IRStmt_Dirty(build_trace_record));

  addStmtToIRSB(bb,
                IRStmt_WrTmp(tmp_retired_instructions_ptr,
                           IRExpr_Binop(IR_ptr_add, IRExpr_RdTmp(tmp_trace_rec_ptr),
                                        IRExpr_Const(IR_const_PTR(CH_OFFSETOF(CH_Record_Exec, instructions_retired))))));

  init_available_expressions();

  for (i = 0; i < bb_in->stmts_used; ++i) {
    IRStmt* st = bb_in->stmts[i];
    if (!st)
      continue;

    switch (st->tag) {
    case Ist_IMark: {
      /* valgrind 3.1 can form traces across call boundaries. This is great,
         because we get longer traces which should give us better
         performance, but it means we have to detect these calls and
         note them in MAP_ENTER_SP.
         The logic here needs to match the bb_in->next logic below, because
         we don't want ENTER_SP generation to depend on whether valgrind
         put the call at the end of the trace or not. So we generate ENTER_SP
         if the transfer is not a fallthrough, and either looks like a call
         or goes to a function entry point. It "looks like a call" if it
         stored the next instruction address (i.e. a return address) somewhere.
      */
      uintptr_t this_addr = (uintptr_t)st->Ist.IMark.addr;
      if (next_instruction_addr &&
          next_instruction_addr != this_addr &&
          (stored_next_instruction_addr || is_function_entry_addr(this_addr))) {
        allocate_bunched_effect(CH_MAP_ENTER_SP, instruction_count - 1,
                                sizeof(void*), 0, True, True);
        add_trace_store_flatten(bb, tmp_trace_rec_ptr, trace_record_offset,
                                IRExpr_Get(layout->offset_SP, IR_ptr_type));
        trace_record_offset += sizeof(uintptr_t);
      }
      stored_next_instruction_addr = False;

      if (st->Ist.IMark.len > 0) {
        /* I don't think the length can be zero, but just in case something pathological
           happens... */
        add_instruction_effect(instruction_count, this_addr, st->Ist.IMark.len);
      }
      next_instruction_addr = this_addr + st->Ist.IMark.len;
      tl_assert2(instruction_count < 255,
                 "Too many instructions in block (%d)!", instruction_count);
      ++instruction_count;

      if (!recorded_instruction_retirement) {
        /* record retirement of previous instruction */
        add_retirement_store(bb, tmp_retired_instructions_ptr,
                             instruction_count - 1);
      }
      recorded_instruction_retirement = False;

      addStmtToIRSB(bb, st);
      break;
    }

    case Ist_Store:
      addStmtToIRSB(bb, st);
      tl_assert2(IR_end == st->Ist.Store.end, "Switched endianness");
      {
        uint8_t dlog2_bytes = get_log2_bytes(bb_in, st->Ist.Store.data);
        IRConst* c = add_trace_store(bb, tmp_trace_rec_ptr, 0,
                                     st->Ist.Store.data);
        intptr_t addr_offset;
        IRTemp addr_temp;
        Bool found_base_temp = find_base_temp(bb_in, i, st->Ist.Store.addr,
                                              &addr_offset, &addr_temp);
        Bool need_offset =
          add_mem_effect(CH_MAP_MEM_WRITE, instruction_count - 1,
                         addr_temp, addr_offset, 1 << dlog2_bytes, c);

        tl_assert2(found_base_temp, "Bad constant offset for store!");
                         
        if (need_offset) {
          add_trace_store(bb, tmp_trace_rec_ptr, trace_record_offset,
                          IRExpr_RdTmp(addr_temp));
          trace_record_offset += sizeof(uintptr_t);
        }

        if (is_constant_address_expression(st->Ist.Store.data, next_instruction_addr)) {
          /* The code is storing the next instruction address.
             This is a heuristic and might change if valgrind decided to decode a
             call to use a non-constant return address, in which case we're hosed! */
          stored_next_instruction_addr = True;
        }
      }
      break;

    case Ist_Put:
      addStmtToIRSB(bb, st);
      {
        uint8_t reg, offset_in_reg;
        if (convert_offset_to_reg(st->Ist.Put.offset, &reg,
                                  &offset_in_reg)) {
          IRConst* off;
          uint8_t dlog2_bytes = get_log2_bytes(bb_in, st->Ist.Put.data);
          uint8_t log2_bytes = get_covering_low_bytes_log2(dlog2_bytes, reg,
                                                           offset_in_reg);
          CH_RegEffect reg_effect =
            { instruction_count - 1, CH_EFFECT_REG_WRITE, log2_bytes, reg, 0, 0 };
          intptr_t offset = 0;
          IRTemp reg_temp = IRTemp_INVALID;
          Bool done_effect = False;
          Bool update_SP = reg == CH_X86_SP;
          
          if (offset_in_reg == 0 &&
              find_base_temp(bb_in, i, st->Ist.Put.data, &offset, &reg_temp)) {
            if (reg_temp == IRTemp_INVALID && offset == (int16_t)offset) {
              /* it's a signed-16-bit constant! */
              reg_effect.type = CH_EFFECT_REG_SETCONST;
              reg_effect.imm0 = offset & 0xFF;
              reg_effect.imm1 = (offset >> 8) & 0xFF;
              add_reg_effect(&reg_effect, NULL, NULL);
              done_effect = True;
            } else {
              int from_reg;
              for (from_reg = 0; from_reg < CH_NUM_REGS && !done_effect; ++from_reg) {
                if (reg_available_expressions[from_reg].temp == reg_temp
                    && reg_available_expressions[from_reg].log2_bytes_available >= dlog2_bytes) {
                  intptr_t delta = offset - reg_available_expressions[from_reg].offset;
                  if (from_reg == reg && delta == (int16_t)delta) {
                    reg_effect.type = CH_EFFECT_REG_ADDCONST;
                    reg_effect.imm0 = delta & 0xFF;
                    reg_effect.imm1 = (delta >> 8) & 0xFF;
                    add_reg_effect(&reg_effect, NULL, NULL);
                    done_effect = True;
                    
                    if (update_SP) {
                      current_SP_offset += delta;
                      /* XXX this is sort of unsafe. Code sequences that add huge values
                         to SP could cause current_SP_offset to look negative here. Oh well. */
                      if ((intptr_t)current_SP_offset >
                          (intptr_t)IR_ptr_constval(last_SP_max_offset)) {
                        IR_ptr_const_set(last_SP_max_offset, current_SP_offset);
                      }
                      update_SP = False;
                    }
                  } else if (delta == (int8_t)delta) {
                    reg_effect.type = CH_EFFECT_REG_ADDREG;
                    reg_effect.imm0 = delta & 0xFF;
                    reg_effect.imm1 = from_reg;
                    add_reg_effect(&reg_effect, NULL, NULL);
                    done_effect = True;
                  }
                }
              }
            }
          }

          if (!done_effect) {
            if (log2_bytes == dlog2_bytes) {
              off = add_trace_store(bb, tmp_trace_rec_ptr, 0, st->Ist.Put.data);
            } else {
              IRExpr* reg_read = add_reg_read(bb, reg, log2_bytes);
              off = add_trace_store(bb, tmp_trace_rec_ptr, 0, reg_read);
            }
            add_reg_effect(&reg_effect, off, NULL);
          }
          
          if (update_SP) {
            /* XXX can we improve performance using regparms? */
            /* XXX would it be better to pass current SP as a parameter? */
            IRExpr** SP_helper_args;
            IRDirty* update_SP_max;
            VexGuestState state;
            
            last_SP_max_offset = IR_const_PTR(0);
            current_SP_offset = 0;
            SP_helper_args = mkIRExprVec_1(IRExpr_Const(last_SP_max_offset));
            update_SP_max =
              unsafeIRDirty_0_N(0, "update_max_SP", update_max_SP, SP_helper_args);
            update_SP_max->needsBBP = True;
            update_SP_max->nFxState = 1;
            update_SP_max->fxState[0].fx = Ifx_Read;
            update_SP_max->fxState[0].offset =
              (char*)&state.VexGuestState_SP - (char*)&state;
            update_SP_max->fxState[0].size = sizeof(state.VexGuestState_SP);
            addStmtToIRSB(bb, IRStmt_Dirty(update_SP_max));
          }

          if (offset_in_reg == 0 && reg_temp != IRTemp_INVALID) {
            reg_available_expressions[reg].temp = reg_temp;
            reg_available_expressions[reg].offset = offset;
            reg_available_expressions[reg].log2_bytes_available = dlog2_bytes;
          }
        }
      }
      break;

    case Ist_PutI:
      addStmtToIRSB(bb, st);
      if (is_x87_IRRegArray(st->Ist.PutI.descr)) {
        IRConst* doff = add_trace_store(bb, tmp_trace_rec_ptr, 0, st->Ist.PutI.data);
        IRExpr* indirect = add_trace_x87_indirect_reg(bb, st->Ist.PutI.ix,
                                                      st->Ist.PutI.bias);
        IRConst* roff = add_trace_store(bb, tmp_trace_rec_ptr, 0, indirect);
        CH_RegEffect effect =
          { instruction_count - 1, CH_EFFECT_DYNREG_WRITE, 3, 0, 0, 0 };
        add_reg_effect(&effect, doff, roff);
      } else if (is_x87Tag_IRRegArray(st->Ist.PutI.descr)) {
        /* do nothing, we (currently) don't care about tags */
      } else {
        ppIRSB(bb_in);
        tl_assert2(0, "Unknown array");
      }
      break;

    case Ist_WrTmp:
      addStmtToIRSB(bb, st);
      {
        IRExpr* expr = st->Ist.WrTmp.data;
        switch (expr->tag) {
        case Iex_Load:
          if (control_flags & CH_INITFLAG_LOG_MEM_READS) {
            uint32_t dlog2_bytes = get_log2_bytes_type(expr->Iex.Load.ty);
            intptr_t addr_offset;
            IRTemp addr_temp;
            Bool found_base_temp = find_base_temp(bb_in, i, expr->Iex.Load.addr,
                                                  &addr_offset, &addr_temp);
            Bool need_offset =
              add_mem_effect(CH_MAP_MEM_READ, instruction_count - 1,
                             addr_temp, addr_offset, 1 << dlog2_bytes, NULL);
            
            tl_assert2(IR_end == expr->Iex.Load.end,
                       "Switched load endianness");
            tl_assert2(found_base_temp, "Bad value for address in load!");

            if (need_offset) {
              add_trace_store(bb, tmp_trace_rec_ptr, trace_record_offset,
                              IRExpr_RdTmp(addr_temp));
              trace_record_offset += sizeof(uintptr_t);
            }
          }
          break;

        case Iex_Get: {
          uint8_t reg, offset_in_reg;
          if (convert_offset_to_reg(expr->Iex.Get.offset, &reg,
                                    &offset_in_reg)) {
            uint8_t log2_bytes = get_log2_bytes_type(expr->Iex.Get.ty);
            if (control_flags & CH_INITFLAG_LOG_REG_READS) {
              CH_RegEffect effect =
                { instruction_count - 1, CH_EFFECT_REG_READ, log2_bytes, reg, 0, 0 };
              add_reg_effect(&effect, NULL, NULL);
            }
            if (offset_in_reg == 0) {
              reg_available_expressions[reg].temp = st->Ist.WrTmp.tmp;
              reg_available_expressions[reg].offset = 0;
              reg_available_expressions[reg].log2_bytes_available = log2_bytes;
            }
          }
          break;
        }

        case Iex_GetI:
          if (control_flags & CH_INITFLAG_LOG_REG_READS) {
            if (is_x87_IRRegArray(expr->Iex.GetI.descr)) {
              IRExpr* indirect = add_trace_x87_indirect_reg(bb, expr->Iex.GetI.ix,
                                                            expr->Iex.GetI.bias);
              IRConst* roff = add_trace_store(bb, tmp_trace_rec_ptr, 0, indirect);
              CH_RegEffect effect =
                { instruction_count - 1, CH_EFFECT_DYNREG_READ, 3, 0, 0, 0 };
              add_reg_effect(&effect, NULL, roff);
            } else if (is_x87Tag_IRRegArray(expr->Iex.GetI.descr)) {
              /* do nothing, we (currently) don't care about tags */
            } else {
              ppIRSB(bb_in);
              tl_assert2(0, "Unknown array");
            }
          }
          break;

        default:
          break;
        }
      }
      break;

    case Ist_Exit:
      tl_assert2(st->Ist.Exit.jk != Ijk_Call, "Call inside a block?");

      can_early_exit = True;

      if (!recorded_instruction_retirement) {
        /* record retirement of this instruction before the conditional
           branch exits the block */
        add_retirement_store(bb, tmp_retired_instructions_ptr,
                             instruction_count);
        recorded_instruction_retirement = True;
      }

      addStmtToIRSB(bb, st);
      break;

    case Ist_Dirty: {
      IRDirty* dirty = st->Ist.Dirty.details;
      int j;
      
      if (control_flags & CH_INITFLAG_LOG_REG_READS) {
        // XXX implement this
        tl_assert2(dirty->mFx != Ifx_Read && dirty->mFx != Ifx_Modify,
                   "Memory-reading dirties not logged yet");

        for (j = 0; j < dirty->nFxState; ++j) {
          IREffect e = dirty->fxState[j].fx;
          int offset = dirty->fxState[j].offset;
          int size = dirty->fxState[j].size;
          uint8_t reg_set[256];
          convert_offsets_to_reg_set(offset, offset + size, reg_set);
          if (e == Ifx_Read || e == Ifx_Modify) {
            int reg;
            for (reg = 0; reg < 256; ++reg) {
              if (reg_set[reg]) {
                CH_RegEffect effect =
                  { instruction_count - 1, CH_EFFECT_REG_READ,
                    get_full_reg_bytes_log2(reg), reg, 0, 0 };
                add_reg_effect(&effect, NULL, NULL);
              }
            }
          }
        }
      }
      
      addStmtToIRSB(bb, st);
      
      if (dirty->mFx == Ifx_Write || dirty->mFx == Ifx_Modify) {
        /* XXX we really should find a way to generate writes of more than 1 byte at a time */
        for (j = 0; j < dirty->mSize; ++j) {
          IRTemp addr = newIRTemp(bb->tyenv, IR_ptr_type);
          IRExpr* taddr = IRExpr_Binop(IR_ptr_add, dirty->mAddr,
                  IRExpr_Const(IR_const_PTR(j)));
          IRTemp tmp_byte = newIRTemp(bb->tyenv, Ity_I8);
          IRConst* c;
          intptr_t addr_offset;
          IRTemp addr_temp;
          Bool found_base_temp;
          Bool need_offset;
          
          addStmtToIRSB(bb, IRStmt_WrTmp(addr, taddr));
          addStmtToIRSB(bb, IRStmt_WrTmp(tmp_byte, IRExpr_Load(Iend_LE, Ity_I8, IRExpr_RdTmp(addr))));

          c = add_trace_store(bb, tmp_trace_rec_ptr, 0, IRExpr_RdTmp(tmp_byte));
          found_base_temp = find_base_temp(bb_in, i, dirty->mAddr,
                                           &addr_offset, &addr_temp);
          need_offset = add_mem_effect(CH_MAP_MEM_WRITE, instruction_count - 1,
                      addr_temp, addr_offset, 1, c);

          tl_assert2(found_base_temp, "Bad constant offset for store!");

          if (need_offset) {
            add_trace_store(bb, tmp_trace_rec_ptr, trace_record_offset,
                    IRExpr_RdTmp(addr_temp));
            trace_record_offset += sizeof(uintptr_t);
          }
        }
      }
      
      for (j = 0; j < dirty->nFxState; ++j) {
        IREffect e = dirty->fxState[j].fx;
        int offset = dirty->fxState[j].offset;
        int size = dirty->fxState[j].size;
        uint8_t reg_set[256];
        convert_offsets_to_reg_set(offset, offset + size, reg_set);
        if (e == Ifx_Write || e == Ifx_Modify) {
          int reg;
          /* XXX we really should find a way to generate writes of more than 1 byte at a time */
          for (reg = 0; reg < 256; ++reg) {
            if (reg_set[reg]) {
              uint8_t log2_bytes = get_full_reg_bytes_log2(reg);
              CH_RegEffect effect =
                { instruction_count - 1, CH_EFFECT_REG_WRITE,
                  log2_bytes, reg, 0, 0 };
              IRExpr* reg_read = add_reg_read(bb, reg, log2_bytes);
              IRConst* off = add_trace_store(bb, tmp_trace_rec_ptr, 0, reg_read);
              add_reg_effect(&effect, off, NULL);
            }
          }
        }
      }
      break;
    }
      
    default:
      addStmtToIRSB(bb, st);
    }
  }

  if (!recorded_instruction_retirement) {
    /* record retirement of final instruction */
    add_retirement_store(bb, tmp_retired_instructions_ptr, instruction_count);
  }

  if (can_early_exit) {
    build_trace_record->cee->name = "prepare_code_record_clean";
    build_trace_record->cee->addr = prepare_code_record_clean;
  }

  tl_assert2(trace_record_offset == align_size_to_pointer(trace_record_offset),
             "Unaligned offset on entry %x\n", trace_record_offset);

  /* record non-fallthrough control transfers as calls if they look like
     calls. Needs to match logic in IMark case above.

     Here, we say "looks like a call" if it's a call instruction (stored
     return address and transfers control) or a direct jump to an instruction
     entry, OR if it's an indirect jump and *at runtime* the target is
     a function entry. The latter is not handled in the IMark case because
     indirect jumps can only appear at the end of bb blocks.
     */
  if (!is_constant_address_expression(bb_in->next, next_instruction_addr) &&
      (bb_in->jumpkind == Ijk_Call || bb_in->jumpkind == Ijk_Boring) &&
      (stored_next_instruction_addr || bb_in->next->tag != Iex_Const ||
       is_function_entry(bb_in->next))) {
    IRExpr* SP_expr = IRExpr_Get(layout->offset_SP, IR_ptr_type);

    if (!stored_next_instruction_addr && bb_in->next->tag != Iex_Const) {
      /* This is an indirect jump. It could be some kind of switch construct,
         or it could be an indirect tail call (this is common in PLT thunks).
         Handle this by doing a runtime check and if it's a jump to a non-
         function, smash the SP value to zero. */
      IRTemp SP_temp = newIRTemp(bb->tyenv, IR_ptr_type);
      IRExpr** args = mkIRExprVec_2(bb->next, IRExpr_RdTmp(SP_temp));

      addStmtToIRSB(bb, IRStmt_WrTmp(SP_temp, SP_expr));
      SP_expr = mkIRExprCCall(IR_ptr_type, 0, "check_function_target",
                              check_function_target, args);
    }

    allocate_bunched_effect(CH_MAP_ENTER_SP, instruction_count - 1,
                            sizeof(void*), 0, True, True);
    add_trace_store_flatten(bb, tmp_trace_rec_ptr, trace_record_offset,
                            SP_expr);
    trace_record_offset += sizeof(uintptr_t);
  }

  reg_log_offset = allocate_bunch_effech_trace_offsets(trace_record_offset);
  /* the reg-effect log may have 'holes' due to alignment optimization.
     These holes should be zeroed out IF we haven't already cleaned
     the record. */
  trace_record_offset =
    allocate_reg_effech_trace_offsets(bb, reg_log_offset,
                                      can_early_exit ? IRTemp_INVALID : tmp_trace_rec_ptr);
  trace_record_offset = align_size_to_pointer(trace_record_offset);
  IR_ptr_const_set(final_record_length, trace_record_offset);

  is_new = allocate_code_index(&code_index);
  IR_ptr_const_set(final_code_index, code_index);

  if (is_new) {
    bunched_effects_used_size = bunched_effech_count*sizeof(CH_BunchedEffect);
    reg_effects_used_size = reg_effech_count*sizeof(CH_RegEffect);
    r = (CH_Record_DefineCode*)
      prepare_record(CH_DEFINE_CODE,
                     align_size_to_pointer(align_size_to_pointer(sizeof(CH_Record_DefineCode))
                                           + bunched_effects_used_size
                                           + reg_effects_used_size));
    r->code_index = code_index;
    r->num_instructions = instruction_count;
    r->num_bunched_effects = bunched_effech_count;
    r->num_reg_effects = reg_effech_count;
    tl_assert2(trace_record_offset - reg_log_offset < 0x10000,
               "Reg log overflow (%d)", trace_record_offset - reg_log_offset);
    r->reg_log_size = (uint16_t)(trace_record_offset - reg_log_offset);
    define_code_output = (uint8_t*)align_to_pointer(r + 1);
    VG_(memcpy)(define_code_output, bunched_effects, bunched_effects_used_size);
    define_code_output += bunched_effects_used_size;
    VG_(memcpy)(define_code_output, reg_effects, reg_effects_used_size);
  }

  if (trace_this) {
    ppIRSB(bb_in);
    ppIRSB(bb);
  } else {
    if (0) ppIRSB(bb);
  }

  return bb;
}

static void ch_post_mem_write(CorePart part, ThreadId tid, Addr a, SizeT len)
{
  if (len > 0) {
    CH_Record_SystemWrite* r = (CH_Record_SystemWrite*)
      prepare_record(CH_SYSTEM_WRITE, sizeof(CH_Record_SystemWrite));
    r->address = (uintptr_t)a;
    r->length = (uintptr_t)len;

    do_bulk_write(a, len);
  }
}

static void ch_pre_mem_read(CorePart part, ThreadId tid, Char* msg,
                            Addr a, SizeT len)
{
  if ((control_flags & CH_INITFLAG_LOG_MEM_READS) && len > 0) {
    CH_Record_SystemRead* r = (CH_Record_SystemRead*)
      prepare_record(CH_SYSTEM_READ, sizeof(CH_Record_SystemRead));
    r->address = (uintptr_t)a;
    r->length = (uintptr_t)len;
  }
}

static void ch_pre_mem_read_asciiz(CorePart part, ThreadId tid, Char* msg,
                                   Addr a)
{
  if (control_flags & CH_INITFLAG_LOG_MEM_READS) {
    CH_Record_SystemRead* r = (CH_Record_SystemRead*)
      prepare_record(CH_SYSTEM_READ, sizeof(CH_Record_SystemRead));
    r->address = (uintptr_t)a;
    /* XXX This is incorrect! But figuring out the correct length is
       hard without crashing! */
    r->length = 1;
  }
}

static void ch_fini(Int exitcode)
{
  if (tracing_enabled) {
    disable_tracing();
  }
}

static void ch_pre_clo_init(void)
{
   VG_(details_name)            ("Chronicle");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("Chronicle tracing engine");
   VG_(details_copyright_author)("Copyright (C) 2006 Novell.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);
   VG_(details_avg_translation_sizeB) ( 175 );

   VG_(basic_tool_funcs)          (ch_post_clo_init,
                                   ch_instrument,
                                   ch_fini);

   init_IR_constants();
   tracing_enabled = True;

   VG_(track_post_mem_write)(ch_post_mem_write);
   VG_(track_pre_mem_read)(ch_pre_mem_read);
   VG_(track_pre_mem_read_asciiz)(ch_pre_mem_read_asciiz);
}

VG_DETERMINE_INTERFACE_VERSION(ch_pre_clo_init)
