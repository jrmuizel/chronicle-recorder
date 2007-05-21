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

#ifndef DEBUG_INTERNALS_H_
#define DEBUG_INTERNALS_H_

#include "query.h"
#include "debug.h"

/*
 * This file contains generic APIs that can be used by particular debuginfo
 * modules (e.g. debug_dwarf2) to communicate with the rest of the system. In
 * particular we expose APIs for accessing program state.
 */

typedef struct {
  uintptr_t            defining_object_offset;
  const char*          name;
  CH_Address           address;
  CH_DbgCompletionKind kind;
  uint8_t              is_partial;
} CH_DbgGlobalSymbol;

typedef struct _DebugObject DebugObject;

/**
 * Add a set of symbols to the global symbol table. Hands ownership from
 * the debug info processor to the debuginfo core. The 'name' data must
 * live forever. This must only be called during dwarf2_load_global_symbols.
 */
void dbg_add_global_symbols(uint32_t num_symbols, DebugObject* defining_object,
                            CH_DbgGlobalSymbol* symbols);
/**
 * Add a set of file names to the global file name table. The name data must 
 * live forever.
 */
void dbg_add_file_names(uint32_t num_files, DebugObject* defining_object,
                        const char** file_names);

/**
 * Wait for global symbols to be fully loaded by the symbol loader thread.
 */
void dbg_wait_for_global_symbols(QueryThread* q);

/**
 * This represents a program state. It is passed to debug info processors
 * to allow them to read memory and registers to determine run-time variable
 * values.
 */
typedef struct {
  CH_TStamp tstamp;
  void*     closure;
} CH_DbgProgramState;

/**
 * Debug info processors can call this to read memory from a program state.
 * Each byte in 'valid' is set to 1 if we succeeded in reading the
 * corresponding byte in 'result'.
 * Returns false on failure.
 */
int dbg_read_memory(CH_DbgProgramState* state, CH_Address addr, uint32_t len,
                    uint8_t* result, uint8_t* valid);
/**
 * Debug info processors can call this to read registers in a program state.
 * Reads least significant 'size' bytes of reg.
 * Returns false on failure.
 */
int dbg_read_reg(CH_DbgProgramState* state, uint8_t reg, uint8_t size,
                 uint8_t* result);

typedef enum {
  CH_TYPE_UNKNOWN,
  CH_TYPE_ANNOTATION,
  CH_TYPE_POINTER,
  CH_TYPE_INT,
  CH_TYPE_FLOAT,
  CH_TYPE_ENUM,
  CH_TYPE_TYPEDEF,
  CH_TYPE_STRUCT,
  CH_TYPE_ARRAY,
  CH_TYPE_FUNCTION
} CH_DbgTypeKind;
typedef enum {
  CH_STRUCT_KIND_STRUCT,
  CH_STRUCT_KIND_CLASS,
  CH_STRUCT_KIND_UNION
} CH_DbgStructKind;
typedef enum {
  CH_ANNOTATION_CONST,
  CH_ANNOTATION_VOLATILE,
  CH_ANNOTATION_RESTRICT
} CH_DbgAnnotationKind;

#endif /*DEBUG_INTERNALS_H_*/
