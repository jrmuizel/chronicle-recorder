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

#ifndef EFFECTMAP_H__
#define EFFECTMAP_H__

/* API to write effect maps to the trace database */

#include "log_stream.h"
#include "compressor.h"
#include "thread_util.h"
#include "database_write.h"

#include <stdint.h>

/**
 * Running data for each page. Except where noted this data is only
 * touched by the main thread.
 */
typedef struct {
  uintptr_t          page_num;

  CH_TStamp          base_tstamp;
  CH_TStamp          last_tstamp;
  uintptr_t*         access_bitmap;
  CH_EffectItem*     access_list;
  CH_GrowBuf         access_data;
  uint32_t           access_count;
  uint32_t           access_data_count;

  /* These fields may be accessed by any thread but the mutex in the
   * CH_EffectMap must be held. History-writing threads store the offsets
   * of their written chunks in here. */
  uint32_t           bitmap_entry_count;
  uint32_t           history_entry_count;
  CH_GrowBuf         bitmap_entries;
  CH_GrowBuf         history_entries;
  /* End thread-shared fields. */

  uint32_t           history_last_tstamp_offset;
  uint16_t           history_last_offset;

  CH_CompressorState compressed_bitmap_buf;
} CH_EffectPageRecord;

/** Hashtable mapping pages to CH_EffectPageRecords */
typedef struct {
  CH_EffectPageRecord** table;
  uint32_t              table_size;
  uint32_t              table_count;
} CH_AddrHash;

/**
 * Running data for an effect map. This data is only accessed by the main
 * thread.
 */
typedef struct {
  CH_AddrHash     pages;
  CH_DBFile*      db;
  uint32_t        access_list_length;
  uint8_t         map_num;
  pthread_mutex_t mutex;
  CH_Semaphore    task_semaphore;
} CH_EffectMap;

/**
 * Initialize a CH_EffectMap. access_list_length is the maximum
 * access list length allowed before we start a new history entry.
 * map_num is a CH_MAP_* constant.
 */
void effect_map_init(CH_EffectMap* map, uint8_t map_num, CH_DBFile* db,
                     uint32_t access_list_length);
/**
 * Append an (bunched) effect to the map. There is no extra data associated
 * with the effect.
 */
void effect_map_append(CH_EffectMap* map, CH_TStamp tstamp,
                       uintptr_t addr, uintptr_t length,
                       CH_BunchedEffectAtoms atoms);
/**
 * Append an (bunched) effect to the map. Effect data is provided with one
 * byte of data per byte affected.
 */
void effect_map_append_isodata(CH_EffectMap* map, CH_TStamp tstamp,
                               uintptr_t addr, uintptr_t length,
                               CH_BunchedEffectAtoms atoms,
                               void* data);
/**
 * Append an (bunched) effect to the map. Effect data is provided with a fixed
 * amount of data for the entire effect.
 */
void effect_map_append_tag(CH_EffectMap* map, CH_TStamp tstamp,
                           uintptr_t addr, uintptr_t length,
                           void* data, uintptr_t data_size);

/**
 * This function queues up threaded work for this map that must be completed
 * before finishing the map. effect_map_finish will block until this work is
 * completed. Exposing this here allows the caller to queue up the maximal
 * amount of threaded work.
 */
void effect_map_prefinish(CH_EffectMap* map);

/**
 * Wait for effect data to finish writing to the database and write out
 * the effect directory entry with the given name.
 */
void effect_map_finish(CH_EffectMap* map, char const* name);

#endif
