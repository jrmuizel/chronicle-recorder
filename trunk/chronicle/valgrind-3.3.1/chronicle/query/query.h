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

#ifndef QUERY_H_
#define QUERY_H_

/* Interfaces to access the global state of the query process. */

#include <stdint.h>
#include <pthread.h>
#include <stdarg.h>

#include "json.h"
#include "thread_util.h"
#include "database_read.h"

/**
 * State for a thread that's processing a query. See protocol.html.
 */
typedef struct {
  /** immutable query ID */
  int64_t  id;
  /** index of this structure in the global QueryThread array */
  int      index;

  /** set to true if we have received a client cancel for this query */
  uint8_t  cancelled;

  /** This lock protects access to the following fields */
  pthread_mutex_t mutex;
  /**
   * Amount of progress required for query to complete (may increase during
   * query processing
   */
  int64_t         progress_max;
  /** Amount of progress completed so far */
  int64_t         progress;
  /** Set to true when we have sent a termination message for this query */
  uint8_t         sent_termination;
} QueryThread;

typedef struct _CH_EffectMapReader CH_EffectMapReader;

/** The global database we're using */
CH_DBFileReader* get_db();
/**
 * Load data for a database directory entry. Returns a pointer to the
 * malloced data. *count returns the number of entries in the returned table.
 * 'section' is the directory entry name, 'entry_size' is the size in bytes of
 * each entry.
 */
void* load_table(const char* section, uint32_t entry_size, uintptr_t* count);

/**
 * Returns the effect-map for memory writes.
 */
CH_EffectMapReader* get_builtin_write_map();

/** Addresses in virtual memory */
typedef uintptr_t CH_Address;
/** Signed addresses in virtual memory (DWARF2 needs this, ugh) */
typedef intptr_t  CH_SignedAddress;

typedef struct {
  CH_Address start;
  CH_Address length;
} CH_Range;

#ifdef CH_X86
#define CH_NUM_REGS   CH_X86_NUM_REGS
#else
#error "Only x86/AMD64 supported at this time"
#endif

/** Pseudoregister: current program counter */
#define CH_REG_PC     (CH_NUM_REGS)
/** Pseudoregister: current thread ID */
#define CH_REG_THREAD (CH_NUM_REGS+1)
#define CH_REG_MAX    CH_REG_THREAD

/* Handy reporting routines */

/** Send a JSON message object to the client */
void debugger_output(JSON_Builder* builder);

/**
 * Send an info-level string to the client regarding some query. q can be
 * NULL if no particular query is related.
 */
void debugger_info(QueryThread* q, const char* code, const char* en_format, ...);
/**
 * Send a warning-level string to the client regarding some query. q can be
 * NULL if no particular query is related.
 */
void debugger_warning(QueryThread* q, const char* code, const char* en_format, ...);
/**
 * Send an error-level string to the client regarding some query. q can be
 * NULL if no particular query is related. If q is non-NULL, the query is
 * terminated.
 */
void debugger_error(QueryThread* q, const char* code, const char* en_format, ...);
/**
 * Send an error-level string to the client regarding some query. q can be
 * NULL if no particular query is related. Terminates this process.
 */
void debugger_fatal_error(QueryThread* q, const char* code, const char* en_format, ...);

/**
 * Send an info-level string to the client regarding some query. q can be
 * NULL if no particular query is related.
 */
void debugger_info_v(QueryThread* q, const char* code, const char* en_format, va_list args);
/**
 * Send a warning-level string to the client regarding some query. q can be
 * NULL if no particular query is related.
 */
void debugger_warning_v(QueryThread* q, const char* code, const char* en_format, va_list args);
/**
 * Send an error-level string to the client regarding some query. q can be
 * NULL if no particular query is related. If q is non-NULL, the query is
 * terminated.
 */
void debugger_error_v(QueryThread* q, const char* code, const char* en_format, va_list args);
/**
 * Send an error-level string to the client regarding some query. q can be
 * NULL if no particular query is related. Terminates this process.
 */
void debugger_fatal_error_v(QueryThread* q, const char* code, const char* en_format, va_list args);

/**
 * This adds work_amount to the progress_max of the query. This should be balanced
 * by a call to complete_work.
 */
void add_work(QueryThread* q, int work_amount);
/**
 * Do some work in a worker thread. We make a malloc'ed copy of the closure
 * record to be passed to the function, so the function should free the
 * closure.
 * 
 * This adds work_amount to the progress_max of the query. This should be balanced
 * by a call to complete_work.
 */
void spawn_work(QueryThread* q, CH_ThreadProc fun, void* closure,
                int closure_size, int work_amount);
/**
 * Signals that progress has been made on the query. 'amount' is added
 * to 'progress'. If progress == progress_max then the query has completed
 * and the query is removed from the active query table.
 * 
 * If non-NULL, the builder contains a partial response object. If the query
 * has not been cancelled, then we fill in the 'id', 'progress',and
 * 'progressMax' fields and send the response to the debugger. If the query
 * has terminated (progress == progress_max) then we also fill in the
 * 'terminated' field, remove the query from the active query table,
 * and free its memory.
 */
int complete_work(QueryThread* q, int amount, JSON_Builder* builder);

#endif /*QUERY_H_*/
