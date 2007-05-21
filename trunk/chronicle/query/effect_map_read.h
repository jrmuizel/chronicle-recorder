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

#ifndef EFFECT_MAP_READ_H__
#define EFFECT_MAP_READ_H__

#include "database.h"
#include "query.h"

/*
 * Declarations of functions for querying effect maps.
 */

typedef struct {
  CH_EffectPageEntry     db_entry;
  CH_EffectHistoryEntry* history_entries;
  CH_EffectBitmapEntry*  bitmap_entries;
} CH_EffectMapReaderPage;

struct _CH_EffectMapReader {
  CH_EffectMapReaderPage** hash_table;
  const char*              name;
  CH_EffectDBMap           hash_info;
  uint32_t                 fixed_data_size;
  uint8_t                  has_data;
};

/**
 * Scans can do three things:
 * -- find all accesses in the given time interval to the given ranges
 * -- find the first access in the given time interval to any byte in the given
 * ranges. We return all accesses within the range that occur with the same
 * timestamp.
 * -- for each byte in the given ranges, find the first access in the time
 * interval. If some byte in the ranges is accessed multiple times with the
 * same timestamp, we may only return one of the accesses (the 'earliest' one).
 * 
 * In the latter two cases we may return additional spurious accesses also,
 * accesses that are in fact not the first over the whole range or for a given
 * byte.
 * When the direction is -1, 'first' means 'last in time'.
 */
typedef enum {
  MODE_FIND_ALL,
  MODE_FIND_FIRST_ANY,
  MODE_FIND_FIRST_COVER
} CH_EffectScanMode;

/**
 * Initialize an effect reader to read the database item named 'name' in the
 * database directory.
 * 'has_data' specifies whether the effects have data associated with them.
 * When there is data, 'fixed_data_size' specifies the size of the data
 * record associated with each effect; if zero, the data size is equal to the
 * number of bytes affected.
 */
void effect_map_reader_init(CH_EffectMapReader* r, const char* name,
                            uint8_t has_data, uint32_t fixed_data_size);

const char* effect_map_reader_get_name(CH_EffectMapReader* r);

/**
 * Start a scan for accesses in the map. This spawns various worker threads to
 * perform the scan asynchronously. The caller can determine when the work is
 * done by passing in a completion_semaphore and then waiting for it to empty.
 * 
 * Address map changes are included as accesses, and can count as the
 * "first access".
 * 
 * If the callback returns zero then we abort the scan as soon as possible
 * (although additional results may still be returned).
 * 
 * Results are returned strictly in timestamp order according to 'direction'.
 * 
 * When the result is ACCESS_MMAP, then 'data' points into the map_operations
 * array of the CH_MemMapHistory returned by
 * find_memory_map_history_for(start_addr). Otherwise 'data' is the data
 * associated with the access by the map.
 */
typedef enum {
  ACCESS_NORMAL,
  ACCESS_MMAP
} CH_EffectScanResult;
typedef int (* CH_EffectMapReaderScanResultCallback)(void* callback_closure,
  QueryThread* query, CH_EffectMapReader* reader, CH_TStamp tstamp,
  CH_Address start_addr, CH_Address end_addr, CH_EffectScanResult result, void* data);
/**
 * Scans until the callback returns 0 or we reach the end of the search.
 * @param ranges we report accesses that intersect one of these ranges;
 * this function takes ownership of the memory
 * @param callback the function that gets called when results have been obtained
 * @param direction 1 to proceed from begin_tstamp to end_tstamp, -1 to
 * proceed from end_tstamp to begin_tstamp
 * @param begin_tstamp the first timestamp to consider
 * @param end_tstamp one beyond the last timestamp to consider; the range
 * of interest is [begin_tstamp, last_tstamp)
 * @param completion_semaphore a semaphore that gets signalled when the query is
 * completed, or NULL if not required
 * @param abortable true if you want to be able to abort by returning zero
 * from the callback
 */
void effect_map_reader_do_scan(CH_EffectMapReader* reader, QueryThread* q,
                               CH_TStamp begin_tstamp, CH_TStamp end_tstamp,
                               CH_Range* ranges, uint32_t num_ranges,
                               CH_EffectScanMode mode, int direction,
                               int abortable,
                               CH_EffectMapReaderScanResultCallback callback,
                               void* callback_closure,
                               CH_Semaphore* completion_semaphore);

/**
 * When an MMAP callback is issued by the scanner, this utility function will
 * fill 'buf' with the data for the mmap, if available. Better not call it
 * if the memory is not mapped.
 * Returns null on failure.
 */
int obtain_memory_contents_from_mmap_callback(QueryThread* q,
  CH_Address start_addr, CH_Address end_addr, void* data, void* buf);
                          
#endif
