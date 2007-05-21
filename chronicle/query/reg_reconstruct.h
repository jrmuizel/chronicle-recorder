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

#ifndef REG_RECONSTRUCT_H_
#define REG_RECONSTRUCT_H_

/* Routines for reconstructing register values. */

#include "database.h"
#include "query.h"

/** Initialize global reconstruction data from the global database. */
void reg_init(void);

/**
 * Returns an array of CH_REG_MAX entries, giving the size in bytes of
 * each register.
 */
uint8_t* get_register_byte_sizes();

/**
 * This callback gets called when we have determined the value of a register.
 */
typedef int (* CH_RegReaderResultCallback)(void* callback_closure,
  QueryThread* query, uint8_t reg, uint8_t bytes, void* value);

/**
 * We call the callback for each requested register (i.e.
 * reg_bytes_requested[reg] > 0). We pass a pointer to the register data in the
 * native format.
 * 
 * If the callback returns zero, we stop early.
 * 
 * @param reg_bytes_requested an array mapping each register value to the
 * number of low bytes of the register to be returned. We may call back
 * with more bytes than requested. The array must be of size CH_REG_MAX.
 */
void reg_read(QueryThread* q, CH_TStamp tstamp, uint8_t* reg_bytes_requested,
              CH_RegReaderResultCallback callback, void* callback_closure);

/**
 * This callback gets called when we have detected a write to a register.
 */
typedef int (* CH_RegWriteScanResultCallback)(void* callback_closure,
  QueryThread* query, CH_TStamp tstamp, uint8_t reg);

/**
 * Scan through the writes to registers of interest on the given thread.
 * If the callback returns zero, we stop early.
 * 'direction' is either 1 or -1 and controls which direction in time
 * we're searching.
 * XXX right now only -1 is supported!
 * Backwards searches exclude writes by instructions at time 'tstamp'.
 * If non-NULL, 'completion_semaphore' is signalled when
 * the search is complete.
 */
void reg_scan_for_write(QueryThread* q, CH_TStamp tstamp,
                        uint32_t pthread_cookie, int direction,
                        uint8_t* reg_bytes_requested,
                        CH_RegWriteScanResultCallback callback,
                        void* callback_closure,
                        CH_Semaphore* completion_semaphore);

/**
 * Scan for SP values greater than the given limit. We return the index
 * of the first instruction in the tstamp range which sets the stack
 * pointer to something greater than 'limit'. If there is no such
 * instructionl, we return end_tstamp.
 * Returns 0 on failure.
 */
CH_TStamp reg_scan_for_SP_greater_than(QueryThread* q, CH_TStamp begin_tstamp,
                                       CH_TStamp end_tstamp,
                                       uint32_t pthread_cookie, CH_Address limit);

#endif /*REG_RECONSTRUCT_H_*/
