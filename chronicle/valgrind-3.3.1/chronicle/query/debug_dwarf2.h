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

#ifndef DEBUG_DWARF2_H_
#define DEBUG_DWARF2_H_

#include "debug.h"
#include "debug_internals.h"
#include "json.h"

/*
 * Utilities for processing DWARF2 debug information in ELF files.
 * These functions all deal with file offsets; these functions do not know
 * how the file is mapped into virtual memory and do not deal with timestamps.
 */

/** An object encapsulating the DWARF2 information in an executable file. */
typedef struct _CH_DbgDwarf2Object CH_DbgDwarf2Object;
/**
 * Support 32-bit DWARF2 on 32-bit architectures and both 32-bit and 64-bit
 * DWARF2 on 64-bit architectures.
 */
typedef uintptr_t CH_DbgDwarf2Offset;

/**
 * Load debug information from the object.
 * Takes ownership of fd. Copies 'name'. Returns NULL on failure.
 */
CH_DbgDwarf2Object* dwarf2_load(int fd, const char* name);
/**
 * Adds all global symbols in the file to the global symbol table via
 * dbg_add_global_symbols. Can be called on any thread. Only this function
 * is allowed to call dbg_add_global_symbols. This is a potentially
 * long-running operation.
 * Also loads filenames via dbg_add_file_names. Only this function is allowed
 * to call dbg_add_file_names.
 */
void dwarf2_load_global_symbols(CH_DbgDwarf2Object* obj,
                                DebugObject* obj_external);
/**
 * Destroy the DWARF2 data object.
 */
void dwarf2_close(CH_DbgDwarf2Object* obj);

/**
 * Data about an instruction's line/column information.
 */
typedef struct {
  const char* file_name; /* immortal, caller does not free */
  uint32_t    line_number;
  uint32_t    column_number;
} CH_DbgDwarf2LineNumberEntry;

/**
 * Retrieve the source line/column info for each address (source line
 * addr <= given addr), storing the result into the caller-supplied 'lines'.
 * If no line information is available, the 'lines' entry will be zeroed.
 *
 * If 'next_lines' is non-NULL, information on the next source line will be
 * provided, if available, otherwise the 'next_lines' entry will be zeroed.
 *
 * Returns false on failure; the state of lines and next_lines is undefined in
 * such a case.
 */
int dwarf2_get_source_info(QueryThread* q, CH_DbgDwarf2Object* obj,
                           CH_DbgDwarf2Offset defining_object_offset,
                           CH_Address* file_offsets,
                           uint32_t file_offsets_count,
                           CH_DbgDwarf2LineNumberEntry* sources,
                           CH_DbgDwarf2LineNumberEntry* next_sources);

/**
 * Strings describing the compilation unit.
 */
typedef struct {
  /* Receiver does not free any of these, they are immortal */
  const char* language;
  const char* compilation_unit;
  const char* compilation_unit_dir;
} CH_DbgDwarf2CompilationUnitInfo;

/**
 * Data about a function.
 */
typedef struct {
  /** Entry point to the function in the file */
  CH_Address         entry_point;
  /**
   * First address of real code in the function after the prologue (or
   * entry_point if not known)
   */
  CH_Address         prologue_end;
  /** Offset to type information for the function, or zero if none available */ 
  CH_DbgDwarf2Offset type_offset;
  /** Name of the function, immortal, receiver does not free */
  const char*        name;
  char*              container_prefix;
  char*              namespace_prefix;
  CH_Range*          ranges; /* terminated by a range of length zero */
  
  CH_DbgDwarf2CompilationUnitInfo cu;
} CH_DbgDwarf2FunctionInfo;

#define DWARF2_FUNCTION_ADDRESS      0x01
#define DWARF2_FUNCTION_IDENTIFIER   0x02
#define DWARF2_FUNCTION_TYPE         0x04
#define DWARF2_FUNCTION_PROLOGUE_END 0x08
#define DWARF2_FUNCTION_RANGES       0x10
#define DWARF2_FUNCTION_ALL          0x1F
/**
 * Retrieve the entry point of a global symbol given its defining offset
 * (as passed by dwarf2_load_global_symbols). The entry point returned is
 * relative to the start of the file. If unavailable, we return zero for
 * the entry point.
 * We also retrieve the identifier data.
 * 'flags' controls what is actually returned.
 * Returns false on failure.
 */
int dwarf2_lookup_function_info(QueryThread* q,
    CH_DbgDwarf2Object* obj, CH_DbgDwarf2Offset function_offset,
    uint32_t flags, CH_DbgDwarf2FunctionInfo* info);
/**
 * This must be called after a successful dwarf2_lookup_function_info.
 */
void dwarf2_destroy_function_info(CH_DbgDwarf2FunctionInfo* info);
/**
 * Return in 'result' the dwarf2 function containing the given
 * object file address, or 0 if there is none known.
 * Returns false on failure.
 */
int dwarf2_get_container_function(QueryThread* q, CH_DbgDwarf2Object* obj,
                                  CH_Address addr, CH_DbgDwarf2Offset* result);

/**
 * Different kinds of variables.
 */
typedef enum {
  CH_DWARF2_FORMAL_PARAMETER,
  CH_DWARF2_LOCAL_VARIABLE,
  CH_DWARF2_GLOBAL_VARIABLE
} CH_DbgDwarf2VariableKind;
/**
 * Information that we can retrieve about a variable.
 */
typedef struct {
  /**
   * Variable_offset is zero for the final entry in a variable array. This is
   * just a sentinel.
   */
  CH_DbgDwarf2Offset variable_offset;
  CH_DbgDwarf2Offset type_offset;
  /** Caller does not free this. This can be null if there is no name. */
  const char*        name;
  /**
   * This is true if the variable was generated by the compiler and is not
   * explicitly declared in the source.
   */
  uint8_t            is_synthetic;
} CH_DbgDwarf2VariableInfo;
/**
 * Returns an array of variables associated with some entity, e.g.,
 * a function, compilation unit, or class. If a function is specified then
 * 'pc_addr' represents an address within the function code; we will exclude
 * variables which are not in scope at that address (if that information
 * is available).
 * 
 * Returns null on failure.
 */
CH_DbgDwarf2VariableInfo* dwarf2_get_variables(QueryThread* q, CH_DbgDwarf2Object* obj,
                                               CH_DbgDwarf2Offset container_offset,
                                               CH_Address pc_addr,
                                               CH_DbgDwarf2VariableKind kind);

/**
 * Compute the value of a variable. 'variable_offset' points to the debug
 * information for a variable (e.g. as returned in variable_offset by
 * dwarf2_get_variables). If the variable is a local variable or parameter
 * for a function, function_offset must refer to the debug info for the
 * containing function and pc_addr should contain an address within the
 * function for the current program counter. If the variable is a global,
 * function_offset should be zero.
 * 'state' represents the current program state in which the variable value
 * is to be evaluated.
 * 
 * This function returns the value in an array of pieces of various kinds;
 * pieces frequently describe the location of data (e.g. memory or
 * register) rather than actual data values. Thus we return essentially a
 * (possibly compound) 'lvalue'. This allows clients to more efficiently
 * scan for changes to a variable.
 *
 * If 'valid_instruction_ranges' is non-null, it is initialized to
 * a malloced array of range objects representing the program counter
 * ranges over which the returned lvalue is valid. The array is terminated
 * by a range with length zero. The array pointer may be set to NULL if
 * the range data is not available. Clients can use this feature to help
 * implement scanning for changes to a variable: if a scan reaches outside
 * the valid_instruction_ranges, then the variable has gone out of scope
 * or an optimization has changed the location of the variable and
 * dwarf2_examine_value may need to be called again.
 * 
 * Returns null on failure.
 */
CH_DbgValuePiece* dwarf2_examine_value(QueryThread* q, CH_DbgDwarf2Object* obj,
                                       CH_DbgDwarf2Offset function_offset,
                                       CH_Address pc_addr,
                                       CH_DbgDwarf2Offset variable_offset,
                                       CH_DbgProgramState* state,
                                       CH_Range** valid_instruction_ranges);

/**
 * A structure with the data for a node in DWARF2's type info graph.
 */
typedef struct {
  CH_DbgTypeKind                  kind;
  uint8_t                         is_dynamic;
  uint8_t                         is_declaration_only;
  CH_DbgDwarf2Offset              inner_type_offset; /* including function result type if available */
  const char*                     name;
  char*                           container_prefix; /* malloced, caller must free */
  char*                           namespace_prefix; /* malloced, caller must free */
  int64_t                         bytes_size; /* -1 if not known */
  
  CH_DbgDwarf2CompilationUnitInfo cu;

  intptr_t                        array_length; /* -1 if not known */
  CH_DbgStructKind                struct_kind;
  CH_DbgAnnotationKind            annotation_kind;
  uint8_t                         pointer_is_reference;
  uint8_t                         int_is_signed;
} CH_DbgDwarf2TypeInfo;

/** Retrieve the type info for a given offset. Returns false on failure. */
int dwarf2_lookup_type_info(QueryThread* q, CH_DbgDwarf2Object* obj,
                            CH_DbgDwarf2Offset type_offset,
                            CH_DbgDwarf2TypeInfo* info);

typedef void (* CH_DbgDwarf2EnumValueIterator)
    (void* closure, const char* name, int64_t value);

/**
 * Extract the enum values for an enum type, passing them to the iterator.
 */
int dwarf2_iterate_type_enum_values(QueryThread* q,
    CH_DbgDwarf2Object* obj, CH_DbgDwarf2Offset type_offset,
    CH_DbgDwarf2EnumValueIterator iterator, void* closure);

typedef void (* CH_DbgDwarf2FunctionParameterIterator)
    (void* closure, const char* name, CH_DbgDwarf2Offset type_offset);

/**
 * Extract the function parameters for a function type, passing them to
 * the iterator.
 */
int dwarf2_iterate_type_function_parameters(QueryThread* q,
    CH_DbgDwarf2Object* obj, CH_DbgDwarf2Offset type_offset,
    CH_DbgDwarf2FunctionParameterIterator iterator, void* closure);

typedef void (* CH_DbgDwarf2StructFieldIterator)
    (void* closure, const char* name, int64_t byte_offset,
     CH_DbgDwarf2Offset type_offset, uint8_t is_subobject,
     uint8_t is_synthetic, int32_t byte_size, int32_t bit_offset,
     int32_t bit_size);

/**
 * Extract the field values for a struct type, passing them to the iterator.
 */
int dwarf2_iterate_type_struct_fields(QueryThread* q,
    CH_DbgDwarf2Object* obj, CH_DbgDwarf2Offset type_offset,
    CH_DbgDwarf2StructFieldIterator iterator, void* closure);

#endif /*DEBUG_DWARF2_H_*/
