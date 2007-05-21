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

#include "memory_map.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

static CH_DBAddrMapEntry* address_map_entries;
static uintptr_t address_map_entry_count;

CH_DBAddrMapEntry* get_address_map_entries() {
  return address_map_entries;
}
int get_address_map_entry_count() {
  return address_map_entry_count;
}

static uint32_t map_history_count;
static CH_MemMapHistory* map_history;

static int cmp_address(const void* v1, const void* v2) {
  CH_Address a1 = *(const CH_Address*)v1;
  CH_Address a2 = *(const CH_Address*)v2;
  if (a1 < a2)
    return -1;
  if (a1 > a2)
    return 1;
  return 0;
}

static CH_Address* build_address_list(int* len) {
  /* fill a buffer with all the endpoints of all map/unmap operations,
     then sort, remove duplicates and return the list. Then we can construct
     our CH_MemMapHistory knowing that each segment is affected atomically
     by any given map/unmap operation */
  CH_Address* buf = safe_malloc(sizeof(CH_Address)*address_map_entry_count*2);
  int i;
  int pt;
  for (i = 0; i < address_map_entry_count; ++i) {
    buf[i*2] = address_map_entries[i].address;
    buf[i*2 + 1] = address_map_entries[i].address + address_map_entries[i].length;
  }

  qsort(buf, address_map_entry_count*2, sizeof(CH_Address), cmp_address);
  
  /* remove duplicates */
  pt = 0;
  for (i = 1; i < address_map_entry_count*2; ++i) {
    if (buf[i] != buf[pt]) {
      ++pt;
      buf[pt] = buf[i];
    } 
  }
  *len = pt + 1;
  return safe_realloc(buf, sizeof(CH_Address)*(pt + 1));
}

static CH_MemMapHistory* get_last_memory_map_history() {
  return map_history + map_history_count;
}

static void build_map_history_table() {
  int len;
  CH_Address* addresses = build_address_list(&len);
  uint32_t i;
  if (len < 2)
    fatal_error(55, "No meaningful map information found!");

  map_history_count = len - 1;
  map_history = safe_malloc(map_history_count*sizeof(CH_MemMapHistory));
  for (i = 0; i < map_history_count; ++i) {
    CH_MemMapHistory* map = &map_history[i];
    map->start = addresses[i];
    map->end = addresses[i + 1];
    map->map_operations = NULL;
    map->num_map_operations = 0;
  }
  safe_free(addresses);
  
  for (i = 0; i < address_map_entry_count; ++i) {
    CH_MemMapHistory* map =
        find_memory_map_history_for(address_map_entries[i].address);
    CH_MemMapHistory* map_end = get_last_memory_map_history();
    CH_Address addr_end = address_map_entries[i].address + address_map_entries[i].length;
    while (map < map_end && map->start < addr_end) {
      map->num_map_operations++;
      ++map;
    }
  }

  for (i = 0; i < map_history_count; ++i) {
    CH_MemMapHistory* map = &map_history[i];
    if (map->num_map_operations > 0) {
      map->map_operations = safe_malloc(map->num_map_operations*sizeof(uint32_t));
      map->num_map_operations = 0;
    }
  }

  for (i = 0; i < address_map_entry_count; ++i) {
    CH_MemMapHistory* map =
        find_memory_map_history_for(address_map_entries[i].address);
    CH_MemMapHistory* map_end = get_last_memory_map_history();
    CH_Address addr_end = address_map_entries[i].address + address_map_entries[i].length;
    while (map < map_end && map->start < addr_end) {
      map->map_operations[map->num_map_operations] = i;
      map->num_map_operations++;
      ++map;
    }
  }
}

void memory_map_init() {
  address_map_entries =
    load_table(CH_SECTION_ADDR_MAP, sizeof(CH_DBAddrMapEntry),
               &address_map_entry_count);

  build_map_history_table();
}

CH_MemMapHistory* find_nearest_memory_map_history_for(CH_Address addr) {
  uint32_t start = 0;
  uint32_t end = map_history_count;
  while (end - start > 1) {
    uint32_t mid = (start + end)/2;
    if (addr < map_history[mid].start) {
      end = mid;
    } else {
      start = mid;
    }
  }
  if (start >= map_history_count)
    return NULL;
  if (addr < map_history[start].end)
    return &map_history[start];
  if (start + 1 >= map_history_count)
    return NULL;
  return &map_history[start + 1];
}

CH_MemMapHistory* find_memory_map_history_for(CH_Address addr) {
  CH_MemMapHistory* h = find_nearest_memory_map_history_for(addr);
  if (h && addr >= h->start && addr < h->end)
    return h;
  return NULL;
}

CH_MemMapInfo get_memory_map_info_for(CH_MemMapHistory* history, CH_TStamp tstamp) {
  uint32_t start = 0;
  uint32_t end = history->num_map_operations;
  CH_MemMapInfo r;

  r.map_operation = NULL;
  r.unmap_operation = NULL;
  while (start + 2 <= end) {
    uint32_t mid = (start + end)/2;
    if (address_map_entries[history->map_operations[mid]].tstamp <= tstamp) {
      start = mid;
    } else {
      end = mid;
    }
  }
  
  if (start == end)
    return r;
  if (address_map_entries[history->map_operations[start]].tstamp > tstamp)
    return r;
  if (!address_map_entries[history->map_operations[start]].is_mapped)
    return r;
  r.map_operation = &address_map_entries[history->map_operations[start]];
  if (start + 1 < history->num_map_operations) {
    r.unmap_operation = &address_map_entries[history->map_operations[start + 1]];
  }
  return r;
}

static int cmp_map_operation_time(const void* v1, const void* v2) {
  const uint32_t* i1 = v1;
  const uint32_t* i2 = v2;
  /* just compare where they appear in the log */
  return *i1 - *i2;
}

uint32_t* create_memory_map_history_for(CH_Address start, CH_Address end,
                                        uint32_t* count) {
  CH_GrowBuf buf;
  uint32_t buf_count = 0;

  init_buf(&buf);
  while (start < end) {
    CH_MemMapHistory* h = find_nearest_memory_map_history_for(start);
    if (!h || h->start >= end)
      break;
    ensure_buffer_size(&buf, sizeof(uint32_t)*(buf_count + h->num_map_operations));
    memcpy((uint32_t*)buf.data + buf_count, h->map_operations,
           sizeof(uint32_t)*h->num_map_operations);
    buf_count += h->num_map_operations;
    start = h->end;
  }
  
  /* now sort them */
  qsort(buf.data, buf_count, sizeof(uint32_t), cmp_map_operation_time);
  *count = buf_count;
  return safe_realloc(buf.data, sizeof(uint32_t)*buf_count);
}
