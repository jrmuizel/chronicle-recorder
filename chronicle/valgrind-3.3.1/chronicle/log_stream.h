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

#ifndef LOG_STREAM_H
#define LOG_STREAM_H

#include <stdint.h>

/* 
 * This file defines the "logstream" protocol that the tracer uses
 * to communicate to the indexer.
 */

/* 
   Setup:
 
   The tracer forks off an indexer process. The indexer's stdin/stdout
   are duped to a pipe.  After fork, the indexer creates a file to be
   used as shared memory and sends the name to the tracer followed by
   a 0 byte. They both mmap the file (not necessarily at the same
   address!).

   Whenever the tracer wants to produce trace data, it requests a trace buffer
   area from the indexer by reading a message from the
   indexer's pipe: a pair of uintptr_t's indicating the start and length
   respectively of the allocated area. At least two buffers should
   be available so that the tracer can fill one buffer while the
   indexer consumes the other. When the tracer is done with a buffer,
   it sends the original offset and length back to the indexer to indicate
   that the area has been filled and released.
*/

#include "arch.h"
#include "effects.h"

/**
 * This record is maintained by the tracer at the start of the shared memory
 * area. The fields are written only by the tracer, never the indexer. The
 * indexer will only look at this data once it has determined that the tracer has
 * terminated, so there are no race conditions.
 * 
 * The tracer records here the start offset and length of the trace buffer it is
 * currently filling, and also the offset of the start of the last trace record.
 * If the tracer exits or crashes unexpectedly, the indexer can use this
 * data to extract every last bit of trace information.
 */
typedef struct {
  uintptr_t last_record;
  struct {
    uintptr_t buffer_start;
    uintptr_t buffer_length;
  } offsets;
} CH_TraceHeader;

/* Architecture-specific definitions */

#ifdef CH_X86
#define CH_STACKPTR           CH_X86_SP /* RSP/ESP */
#define CH_NUM_REGS           CH_X86_NUM_REGS
#if __WORDSIZE == 64
typedef CH_AMD64Context       CH_Context;
#define CH_PTR_LOG2_BYTES     3
#define CH_X86_GP_REGS_COUNT  16
#define CH_X86_SSE_REGS_COUNT 16
#else
typedef CH_X86Context         CH_Context;
#define CH_PTR_LOG2_BYTES     2
#define CH_X86_GP_REGS_COUNT  8
#define CH_X86_SSE_REGS_COUNT 8
#endif
#else
#error Unknown architecture
#endif

#define CH_OFFSETOF(t, f) ((int)(long)(char*)(&((t*)(NULL))->f))

/**
 * A trace buffer is a number of records, each pointer-aligned. Each
 * record starts with a 'code_index' field indicating the record
 * type, unless it is an CH_Record_Exec, in which case it indicates
 * the index of the executed code block. The last record in a trace buffer
 * has code_index CH_END_BUFFER.
 */
#define CH_END_BUFFER 0

typedef struct {
  uint32_t code_index;
  /** length of the whole record, including header */
  uint32_t length;
} CH_RecordHeader;

/**
 * A CH_Record_Exec records the execution of a code block. The code_index
 * is the index of the code block (previously defined via a CH_DEFINE_CODE
 * record).
 * 
 * AFter the fields below, the rest of the exec record looks like this:
 * ... uintptr_t any_dynamic_offsets_of_the_bunched_effects[];  ...
 * ... ([pointeraligned] data_for_each_bunched_effect[])[]; ...
 * ... uint8_t packed_reg_effect_buffer[]; ...
 */
typedef struct {
  CH_RecordHeader header;
  /**
   * The number of instructions retired (which may be less than the number
   * of instructions in the block if the block exited prematurely).
   */
  uint8_t         instructions_retired;
} CH_Record_Exec;

/**
 * Notify that properties of the address space have changed.
 * May be followed by one or more CH_BULK_WRITE messages with the
 * contents.
 * We send a series of these on startup to record the initial state of the
 * address space.
 * 
 * See the definition of CH_DBAddrMapEntry for the meanings of these fields,
 * except for the filename data.
 */ 
#define CH_SET_ADDR_MAP 1
typedef struct {
  CH_RecordHeader header;
  uintptr_t       address;
  uintptr_t       length;
  uint8_t         is_mapped;
  uint8_t         is_read;
  uint8_t         is_write;
  uint8_t         is_execute;
  uint8_t         is_file;
  uint8_t         suppress_debug_info;
  uint8_t         contents_will_follow;
  uint8_t         contents_set_zero;
  uint8_t         contents_from_file;
  uint8_t         contents_unchanged;
  /**
   * When 1, the filename follows this record as a null-terminated UTF8
   * string.
   */
  uint8_t   file_name_follows;

  uintptr_t device;
  uintptr_t inode;
  uint64_t  offset;
} CH_Record_SetAddrMap;

/**
 * Report a mass change to memory. Multiple huge writes can be
 * split into separate messages to avoid trace buffer overflow.
 * 
 * The actual data is in "length" bytes following this record.
 */
#define CH_BULK_WRITE 2
typedef struct {
  CH_RecordHeader header;
  uintptr_t       address;
  uint32_t        length;
} CH_Record_BulkWrite;

/**
 * Report an update to memory by a system call or other external effect.
 * BulkWrite records follow with the actual data.
 */
#define CH_SYSTEM_WRITE 3
typedef struct {
  CH_RecordHeader header;
  uintptr_t       address;
  uintptr_t       length;
} CH_Record_SystemWrite;

/**
 * Report a read to memory by a system call or other external effect. Not
 * all kernel or other external reads can be observed.
 */
#define CH_SYSTEM_READ 4
typedef struct {
  CH_RecordHeader header;
  uintptr_t       address;
  uintptr_t       length;
} CH_Record_SystemRead;

/**
 * Report the creation of a new translation for a code block.
 * 
 * Following the fields below are a sequence of CH_BunchedEffect records
 * and a sequence of CH_RegEffect records.
 */
#define CH_DEFINE_CODE 5
typedef struct {
  CH_RecordHeader header;
  /** The ID of the code block being defined. */
  uint32_t        code_index;
  /** The number of instructions in the block */
  uint16_t        num_instructions;
  /** The number of bunched effects performed by the block. */
  uint16_t        num_bunched_effects;
  /** The number of register effects performed by the block. */
  uint16_t        num_reg_effects;
  /**
   * The (pointer aligned) size of the register log data produced by each
   * execution of this code block.
   */
  uint16_t        reg_log_size;
} CH_Record_DefineCode;

/**
 * Whenever something drastic happens, e.g., a signal, or at startup,
 * or a thread switch, the tracer issues a ResetState to report the the contents
 * of all registers and the current thread ID. This is also issued periodically
 * to bound the cost of register replay.
 */
#define CH_RESET_STATE 6
typedef struct {
  CH_RecordHeader header;
  /**
   * The maximum SP register value since the *last* ResetState (0 if this is
   * the first ResetState).
   */
  uintptr_t       SP_max;
  /** The current thread ID (unique among all IDs for currently live threads) */
  uint32_t        thread_ID;
  /** The current register state. */
  CH_Context      context;
} CH_Record_ResetState;

/**
 * This is the first trace record sent by the tracer.
 */
#define CH_INIT 7
typedef struct {
  CH_RecordHeader header;
  uint32_t        flags;
} CH_Record_Init;
/** The tracer has been configured to log register reads (off by default). */
#define CH_INITFLAG_LOG_REG_READS       0x01
/** The tracer has been configured to log memory reads (off by default). */
#define CH_INITFLAG_LOG_MEM_READS       0x02

#define CH_MAX_BUILTIN_RECORDS 7

#endif
