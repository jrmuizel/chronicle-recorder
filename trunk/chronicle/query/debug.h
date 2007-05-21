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

#ifndef DEBUG_H_
#define DEBUG_H_

#include <stdint.h>
#include "query.h"

/*
 * This file contains an API for accessing generic debug info. It delegates
 * to particular debug info modules (e.g., debug_dwarf2) to collect debugging
 * information from particular object files.
 * 
 * Most of the functions in this API are sensitive to changing memory maps and
 * require a timestamp parameter. For example, when asking which function
 * contains a given address, one must pass a timestamp, because multiple
 * object files may have resided at the given address at different times.
 * 
 * Many of these functions fill JSON data structures with their results.
 * The structure of these JSON objects is documented in protocol.html.
 * We do this instead of returning C data structures because the varying
 * capabilities of debug information providers (and the compilers that
 * generate debug information, and the flags used to invoke those
 * compilers), plus the richness of debug information, means that we need
 * to return the results in very flexible and dynamic data structures, for
 * which JSON is a better fit than C. Also, the primary user of these APIs
 * is going to return JSON to clients anyway.
 */

/** Initialize the debugging subsystem. */
void dbg_init();

/**
 * Gets a file descriptor for file mapped by operation 'e'. Returns NULL
 * if 'e' doesn't correspond to a file map operation or if the original file
 * cannot be found (e.g., the file was anonymous, or we can detect that it
 * has changed).
 */
int dbg_aquire_fd_for_mapped_file(CH_DBAddrMapEntry* e);
/**
 * Release the file descriptor.
 */
void dbg_release_fd_for_mapped_file(CH_DBAddrMapEntry* e, int fd);

typedef struct {
  const char* filename;
  int32_t start_line, start_column;
  int32_t end_line, end_column;
} CH_DbgSourceInfo;

/**
 * Get source information for a given address at a given point in time.
 */
CH_DbgSourceInfo dbg_get_source_info(QueryThread* q, CH_TStamp tstamp,
                                     CH_Address addr);

#define AUTOCOMPLETE_KIND_GLOBAL_TYPE     0x01
#define AUTOCOMPLETE_KIND_GLOBAL_VARIABLE 0x02
#define AUTOCOMPLETE_KIND_GLOBAL_FUNCTION 0x04
typedef uint8_t CH_DbgCompletionKind;
typedef struct {
  /* (an estimate of) the total number of matches that could match the prefix */
  int32_t  total_matches;
  
  int32_t  match_count;
  /* a malloc'ed buffer of 'match_count' null-terminated UTF8 strings;
     caller must free */
  char*    match_names;
  /* a malloc'ed buffer of 'match_count' autocomplete kinds */
  uint8_t* match_kinds;
} CH_DbgCompletionResult;
/**
 * Retrieve global symbols that match a given substring. Retrieves
 * up to 'desired_count' matches starting with the match number given by 'from'.
 */
CH_DbgCompletionResult dbg_auto_complete_global_name(QueryThread* q,
    CH_DbgCompletionKind kinds, const char* prefix, uint8_t case_sensitive,
    int32_t from, int32_t desired_count);

/**
 * Outputs the global function object that contains this
 * address, if any. This is how you find out what function an address is in.
 * Returns false on failure.
 */
int dbg_get_container_function(QueryThread* q, JSON_Builder* builder,
                               CH_TStamp tstamp, CH_Address addr);
/**
 * Outputs an array of the parameters to the function call whose first
 * instruction executes at 'tstamp'.
 * Returns false on failure.
 */
int dbg_get_params(QueryThread* q, JSON_Builder* builder, CH_TStamp tstamp);
/**
 * Outputs an array of the local variables in scope at timestamp 'tstamp'.
 * Returns false on failure.
 */
int dbg_get_locals(QueryThread* q, JSON_Builder* builder, CH_TStamp tstamp);
/**
 * Outputs a typekey for a global types with this name.
 * Returns false on failure.
 */
int dbg_lookup_global_type(QueryThread* q, JSON_Builder* builder,
                           const char* name, const char* namespace_prefix,
                           const char* container_prefix, const char* context_typekey);
/**
 * Outputs a list of the global function objects for global functions
 * with this name.
 */
int dbg_lookup_global_functions(QueryThread* q, JSON_Builder* builder,
                                const char* name);
/**
 * Outputs a list of the global variable objects for global variables
 * with this name.
 */
int dbg_lookup_global_variables(QueryThread* q, JSON_Builder* builder,
                                const char* name);

/**
 * Outputs the type information for the given typekey.
 */
int dbg_lookup_type(QueryThread* q, JSON_Builder* builder, const char* typekey);

/* dbg_examine_value returns the location of a variable. We support
   dependency tracking; the dependency tracker value will be passed
   to each memory/register read so we can see what program state the location
   depends on.
*/

typedef enum {
  CH_PIECE_MEMORY,
  CH_PIECE_REGISTER,
  CH_PIECE_CONSTANT,
  CH_PIECE_UNDEFINED,
  CH_PIECE_ERROR,
  CH_PIECE_END
} CH_DbgValuePieceType;
typedef struct {
  CH_DbgValuePieceType type;
  /* 'source' is an address, register number or the data itself.
     For CH_PIECE_CONSTANT, source_offset_bits must be zero and source_size_bits
     be less than or equal to 8*sizeof(uintptr_t). */
  uintptr_t            source;
  uintptr_t            source_offset_bits;
  /* The size of the last piece may be zero in which case it is understood
     that this piece is "the rest" and must be followed by CH_PIECE_END */
  uintptr_t            source_size_bits;
} CH_DbgValuePiece;

/**
 * If non-null, this callback gets called when we encounter a dependency of
 * the variable value that does not contribute directly to the pieces of the
 * value.
 */
typedef void (* CH_DbgDependencyCallback)(void* closure, CH_DbgValuePiece* piece);

/**
 * Compute the lvalue for a variable as an array of pieces, describing where
 * the value is stored.
 * If non-null, output_valid_instruction_ranges is set to an array of ranges
 * (terminated by a range of length 0); the lvalue is correct as long as the
 * program counter stays in the ranges. The array pointer may be set to NULL
 * if this information is not available.
 */
CH_DbgValuePiece* dbg_examine_value(QueryThread* q, CH_TStamp tstamp,
                                    const char* valkey, const char* typekey,
                                    CH_DbgDependencyCallback dependency_tracker,
                                    void* dependency_tracker_closure,
                                    CH_Range** output_valid_instruction_ranges);

#endif /*DEBUG_H_*/
