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

#ifndef MEMORYMAP_H_
#define MEMORYMAP_H_

/* Interfaces to access the memory map history. There is only one, it's global. */

#include "database.h"
#include "query.h"

/**
 * Load the memory map history data from the database and use it to
 * initialize the global memory map history.
 */
void memory_map_init();

/**
 * Get the array of address map change entries, ordered in increasing order
 * of timestamp.
 */
CH_DBAddrMapEntry* get_address_map_entries();
/**
 * Get the length of the array of address map change entries.
 */
int get_address_map_entry_count();

/**
 * This structure stores the history for a range of memory.
 */
typedef struct {
  /** The start of the memory range. */
  CH_Address start;
  /** The end of the memory range (exclusive). */
  CH_Address end;
  /**
   * Array of indices into array returned by get_address_map_entries;
   * these are the memory map events that affected this range. The entries
   * are in increasing timestamp order.
   */
  uint32_t*  map_operations;
  /** Number of entries. */
  uint32_t   num_map_operations;
} CH_MemMapHistory;
/**
 * Get the history for the virtual memory area containing 'start', or NULL
 * if nothing was ever mapped at that address. The result is owned by
 * the memory_map subsystem, the caller does not need to clean it up.
 */
CH_MemMapHistory* find_memory_map_history_for(CH_Address addr);
/**
 * Get the history for the virtual memory area containing 'start', or if
 * nothing was ever mapped at that address, the history of next upwards
 * ever-mapped virtual memory area, or NULL if there is no such.
 * The result is owned by the memory_map subsystem, the caller does not need
 * to clean it up.
 */
CH_MemMapHistory* find_nearest_memory_map_history_for(CH_Address addr);

/**
 * Get the complete history of all virtual memory operations affecting the range.
 * The result should be freed by the caller. Returns an array of indices
 * into the array returned by get_address_map_entries; *count is the length
 * of the returned array.
 */
uint32_t* create_memory_map_history_for(CH_Address start, CH_Address end,
                                        uint32_t* count);

typedef struct {
  CH_DBAddrMapEntry* map_operation;
  CH_DBAddrMapEntry* unmap_operation;
} CH_MemMapInfo;
/**
 * Find the map operations that bracket 'tstamp'. If the area was
 * not mapped at time 'tstamp' then we return NULL in both cases. If the area
 * was not unmapped or remapped between tstamp and the end of the trace then
 * we return NULL for the unmap_operation. Note that unmap_operation could
 * be an operation that remapped to the area to something else.
 */
CH_MemMapInfo get_memory_map_info_for(CH_MemMapHistory* history, CH_TStamp tstamp);

#endif /*MEMORYMAP_H_*/
