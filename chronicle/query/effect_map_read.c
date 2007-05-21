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

#include "effect_map_read.h"
#include "config.h"
#include "decompression_cache.h"
#include "decompressor.h"
#include "memory_map.h"
#include "debug.h"

#include <string.h>
#include <stdlib.h>

void effect_map_reader_init(CH_EffectMapReader* r, const char* name, uint8_t has_data,
                            uint32_t fixed_data_size) {
  char buf[1024];
  CH_EffectDBMap* data;
  uintptr_t data_len;
  CH_EffectMapReaderPage* pages;
  CH_EffectPageEntry* entries;
  uint32_t* table;
  int i;
  
  snprintf(buf, sizeof(buf), "MAP_%s", name);
  buf[sizeof(buf)-1] = 0;

  data = load_table(buf, 1, &data_len);
  r->name = name;
  r->hash_info = *data;
  r->has_data = has_data;
  r->fixed_data_size = fixed_data_size;
  table = (uint32_t*)(data + 1);
  entries = (CH_EffectPageEntry*)(table + data->page_table_size);

  pages = safe_malloc(sizeof(CH_EffectMapReaderPage)*data->page_entry_count);
  for (i = 0; i < data->page_entry_count; ++i) {
    pages[i].db_entry = entries[i];
    pages[i].history_entries = NULL;
    pages[i].bitmap_entries = NULL;
  }
  r->hash_table = safe_malloc(sizeof(CH_EffectMapReaderPage*)*data->page_table_size);
  for (i = 0; i < data->page_table_size; ++i) {
    r->hash_table[i] = table[i] == 0 ? NULL : &pages[table[i]];
  }
  safe_free(data);
}

const char* effect_map_reader_get_name(CH_EffectMapReader* r) {
  return r->name;
}

static void ensure_entry_lists_loaded(CH_EffectMapReaderPage* p) {
  if (!p || p->history_entries)
    return;

  p->history_entries =
    db_read_alloc(get_db(), p->db_entry.history_entry_fileloc,
                  p->db_entry.history_entry_count*sizeof(CH_EffectHistoryEntry));
  p->bitmap_entries =
    db_read_alloc(get_db(), p->db_entry.bitmap_entry_fileloc,
                  p->db_entry.bitmap_entry_count*sizeof(CH_EffectBitmapEntry));
}

static CH_EffectMapReaderPage* find_page(CH_EffectMapReader* reader, uint64_t page_num) {
  uint32_t hash = hash_page_num(page_num, reader->hash_info.page_table_size);
  for (;;) {
    CH_EffectMapReaderPage* p = reader->hash_table[hash];
    if (!p)
      return NULL;
    if (p->db_entry.page_num == page_num)
      return p;
    ++hash;
    if (hash > reader->hash_info.page_table_size) {
      hash = 0;
    }
  }
}

/**
 * Used to record that we have found a result at timestamp 'value' so
 * no result after 'value' (for MODE_FIND_FIRST) or no result before 'value'
 * for (MODE_FIND_LAST) need be returned.
 */
typedef struct {
  pthread_mutex_t mutex;
  CH_TStamp       value;
  uint32_t        ref_count;
  uint8_t         aborted;
} ScanBound;

static void bound_unreference(ScanBound* bound, int abort) {
  int done;
  if (!bound)
    return;
    
  pthread_mutex_lock(&bound->mutex);
  --bound->ref_count;
  done = bound->ref_count == 0;
  if (abort) {
    bound->aborted = 1;
  }
  pthread_mutex_unlock(&bound->mutex);
  
  if (done) {
    safe_free(bound);
  }
}

typedef struct {
  uint64_t        page_num;
  CH_EffectMapReaderPage* page_data;
  CH_Semaphore*   status_semaphore;
  CH_EffectMapReader* reader;
  QueryThread*    q;
  CH_TStamp       begin_tstamp;
  CH_TStamp       end_tstamp;
  ScanBound*      bound;
  CH_DecompressorBitRunRange* ranges;
  uint32_t        num_ranges;
  CH_EffectScanMode   mode;
  int             direction;
  CH_EffectMapReaderScanResultCallback callback;
  void*           callback_closure;
  uint32_t*       mmap_operations;
  uint32_t        num_mmap_operations;
} PageScanClosure;

static void bound_update_read_only_unlocked(PageScanClosure* cl, uint32_t* num_ranges) {
  ScanBound* bound = cl->bound;
  
  if (bound->aborted) {
    *num_ranges = 0;
    return;
  }
  
  if (cl->mode == MODE_FIND_FIRST_ANY) {
    if (cl->direction > 0) {
      if (bound->value + 1 < cl->end_tstamp) {
        cl->end_tstamp = bound->value + 1;
      }
    } else {
      if (bound->value > cl->begin_tstamp) {
        cl->begin_tstamp = bound->value;
      }
    }
  }
}

/**
 * Abort the query by setting the bounds to be empty.
 */
static void bound_abort(PageScanClosure* cl, uint32_t* num_ranges) {
  ScanBound* bound = cl->bound;
  *num_ranges = 0;
  if (!bound)
    return;
  pthread_mutex_lock(&bound->mutex);
  bound->aborted = 1;
  pthread_mutex_unlock(&bound->mutex);
}

static int bound_check_query_cancelled(PageScanClosure* cl, uint32_t* num_ranges) {
  if (!cl->q->cancelled)
    return 0;

  *num_ranges = 0;
  return 1;
}

static void bound_update_read_only(PageScanClosure* cl, uint32_t* num_ranges) {
  ScanBound* bound = cl->bound;

  if (bound_check_query_cancelled(cl, num_ranges))
    return;
  if (!bound)
    return;

  pthread_mutex_lock(&bound->mutex);
  bound_update_read_only_unlocked(cl, num_ranges);
  pthread_mutex_unlock(&bound->mutex);
}

/**
 * There is a relevant access in [interval_first, interval_last] (inclusive).
 * Update the bound appropriately. Also, use the bound to update our begin/end
 * search timestamps in case someone else found a better match.
 */
static void bound_update(PageScanClosure* cl, CH_TStamp interval_first,
                         CH_TStamp interval_last, uint32_t* num_ranges) {
  ScanBound* bound = cl->bound;

  if (bound_check_query_cancelled(cl, num_ranges))
    return;
  if (!bound)
    return;

  pthread_mutex_lock(&bound->mutex);
  /* even if the bound exists, we might not want to update it normally.
     the bound might be just for callback-directed cancellation. */
  if (cl->mode == MODE_FIND_FIRST_ANY) {
    if (cl->direction > 0) {
      if (bound->value > interval_last) {
        bound->value = interval_last;
      }
    } else {
      if (bound->value < interval_first) {
        bound->value = interval_first;
      }
    }
  }
  bound_update_read_only_unlocked(cl, num_ranges);
  pthread_mutex_unlock(&bound->mutex);
}

typedef struct {
  uint32_t   bitmap_entry;
  int32_t    first_history_entry;
  uint64_t   compressed_data_fileloc;
  uint16_t*  uncompressed_data;
  uint16_t** history_entry_runs;
} LoadedBitmap;

static void loaded_bitmap_destroy(LoadedBitmap* lb) {
  decompression_cache_release(lb->compressed_data_fileloc, lb->uncompressed_data);
  safe_free(lb->history_entry_runs);
}

static uint16_t* load_bitmap_for_history_entry(CH_EffectMapReaderPage* page_data,
    uint32_t history_entry, LoadedBitmap* lb, int* did_work) {
  uint32_t desired_bitmap_entry =
    page_data->history_entries[history_entry].access_bitmap_index;
  *did_work = 0;
  if (desired_bitmap_entry != lb->bitmap_entry) {
    int32_t h;
    CH_EffectBitmapEntry* e = &page_data->bitmap_entries[desired_bitmap_entry];
    uint32_t decompressed_size;
    int32_t history_entry_count;
        
    loaded_bitmap_destroy(lb);

    lb->bitmap_entry = desired_bitmap_entry;
    for (h = history_entry; h > 0; --h) {
      if (page_data->history_entries[h - 1].access_bitmap_index != desired_bitmap_entry)
        break;
    }
    lb->first_history_entry = h;
    for (h = history_entry + 1; h < page_data->db_entry.history_entry_count; ++h) {
      if (page_data->history_entries[h].access_bitmap_index != desired_bitmap_entry)
        break;
    }
    history_entry_count = h - lb->first_history_entry;
    lb->history_entry_runs = safe_malloc(sizeof(uint8_t*)*history_entry_count);
    
    lb->compressed_data_fileloc = e->bitmap_fileloc;
    lb->uncompressed_data =
      decompression_cache_acquire(e->bitmap_fileloc, e->bitmap_compressed_size,
                                  CH_COMPRESSTYPE_BITRUNS, &decompressed_size);
    lb->history_entry_runs[0] = lb->uncompressed_data;
    for (h = 1; h < history_entry_count; ++h) {
      lb->history_entry_runs[h] =
        decompress_skip_bit_run_block(lb->history_entry_runs[h - 1],
                                      1 << CH_EFFECT_MAP_PAGE_SIZE_BITS);
    }
    
    *did_work = 1;
  }

  return lb->history_entry_runs[history_entry - lb->first_history_entry];
}

static int page_scan_end_of_history(PageScanClosure* cl, CH_EffectHistoryEntry* e) {
  if (cl->direction < 0) {
    return e->last_tstamp < cl->begin_tstamp;
  } else {
    return e->first_tstamp >= cl->end_tstamp;
  }
}

static uint32_t uint32_min(uint32_t v1, uint32_t v2) {
  return v1 < v2 ? v1 : v2;
}

static uint32_t uint32_max(uint32_t v1, uint32_t v2) {
  return v1 > v2 ? v1 : v2;
}

static int get_intersection(CH_DecompressorBitRunRange* r1,
    CH_DecompressorBitRunRange* r2, uint32_t* start, uint32_t* end) {
  uint32_t intersect_start = uint32_max(r1->offset, r2->offset);
  uint32_t intersect_end =
    uint32_min(r1->offset + r1->length, r2->offset + r2->length);
  if (intersect_start < intersect_end) {
    *start = intersect_start;
    *end = intersect_end;
    return 1;
  }
  return 0;
}

static int is_in_ranges(uint32_t item_start, uint32_t item_end,
                        CH_DecompressorBitRunRange* ranges,
                        uint32_t num_ranges) {
  int i;
  for (i = 0; i < num_ranges; ++i) {
    uint32_t intersect_start = ranges[i].offset;
    uint32_t intersect_end = ranges[i].offset + ranges[i].length;
    if (intersect_start < item_start) {
      intersect_start = item_start;
    }
    if (intersect_end > item_end) {
      intersect_end = item_end;
    }
    if (intersect_start < intersect_end)
      return 1;
  }
  return 0;
}

static CH_DecompressorBitRunRange* complex_remove_ranges(CH_DecompressorBitRunRange* remove,
                                                         uint32_t num_remove,
                                                         CH_DecompressorBitRunRange* ranges,
                                                         uint32_t* num_ranges) {
  /* allocate an array big enough for all possible ranges. at worst, each
     removed section is in the middle of some input range, so we get a total
     number of range fragments = num_remove + num_ranges. */
  CH_DecompressorBitRunRange* result =
    safe_malloc(sizeof(CH_DecompressorBitRunRange)*(num_remove + *num_ranges));
  uint32_t result_count = 0;
  int i;
  
  for (i = 0; i < *num_ranges; ++i) {
    uint32_t range_start = ranges[i].offset;
    uint32_t range_end = range_start + ranges[i].length;

    while (num_remove && remove->offset + remove->length <= range_start) {
      ++remove;
      --num_remove;
    }

    while (num_remove) {
      uint32_t intersect_start;
      uint32_t intersect_end;
      if (!get_intersection(&ranges[i], remove, &intersect_start, &intersect_end))
        break;

      /* remove intersection from ranges[i] */
      if (intersect_start == range_start) {
        ranges[i].length -= intersect_end - intersect_start;
        ranges[i].offset = intersect_end;
      } else if (intersect_end == range_end) {
        ranges[i].length -= intersect_end - intersect_start;
      } else {
        /* the piece to remove is *inside* ranges[i] and divides it into two.
           Put the first piece in the result array, and trim ranges[i]
           to the second piece. */
        result[result_count].offset = range_start;
        result[result_count].length = intersect_start - range_start;
        ++result_count;
        ranges[i].offset = intersect_end;
        ranges[i].length = range_end - intersect_end;
      }
      
      if (intersect_end == remove->length) {
        ++remove;
        --num_remove;
      } else {
        /* range_end < remove->length, so we're done with this range[i] */
        break;
      }
    }
    
    if (ranges[i].length) {
      result[result_count] = ranges[i];
      ++result_count;
    }
  }

  result = safe_realloc(result, sizeof(CH_DecompressorBitRunRange)*result_count);
  *num_ranges = result_count;
  return result;
}                                         

/**
 * Consumes (modifies) the 'remove' array but does not free it.
 */
static void remove_ranges(CH_DecompressorBitRunRange* remove,
                          uint32_t num_remove,
                          CH_DecompressorBitRunRange** ranges,
                          uint32_t* num_ranges) {
  CH_DecompressorBitRunRange* tmp;
  
  if (num_remove == 0 || *num_ranges == 0)
    return;

  if (num_remove == 1) {
    int i;
    int is_complex = 0;
    
    for (i = 0; i < *num_ranges; ++i) {
      uint32_t intersect_start;
      uint32_t intersect_end;
      if (get_intersection(&(*ranges)[i], remove, &intersect_start, &intersect_end)) {
        uint32_t range_start = (*ranges)[i].offset;
        uint32_t range_end = range_start + (*ranges)[i].length;
        if (intersect_start == range_start && intersect_end == range_end) {
          if (i == *num_ranges - 1) {
            --(*num_ranges);
            return;
          }
          /* treat this as complex ... we could get into a nasty O(N^2) situation
             if we use repeated memmoves to shrink the ranges array */
          is_complex = 1;
          break;
        }
        
        if (intersect_start == range_start) {
          /* remove the intersection from the beginning of the range */
          (*ranges)[i].length -= intersect_end - intersect_start;
          (*ranges)[i].offset = intersect_end;
        } else if (intersect_end == range_end) {
          /* remove the intersection from the end of the range */
          (*ranges)[i].length -= intersect_end - intersect_start;
        } else {
          is_complex = 1;
          break;
        }
      }
    }
    if (!is_complex)
      return;
  }
  
  tmp = complex_remove_ranges(remove, num_remove, *ranges, num_ranges);
  safe_free(*ranges);
  *ranges = tmp;
}

static int report_result(PageScanClosure* cl, CH_TStamp tstamp, uint32_t offset,
                         uint32_t length, uint8_t* data,
                         CH_DecompressorBitRunRange** ranges,
                         uint32_t* num_ranges, int access_type, int can_cover) {
  int i;
  for (i = 0; i < *num_ranges; ++i) {
    uint32_t intersect_start;
    uint32_t intersect_end;
    CH_DecompressorBitRunRange r = {offset, length};
    if (get_intersection(&(*ranges)[i], &r, &intersect_start, &intersect_end)) {
      CH_Address start =
        (cl->page_num << CH_EFFECT_MAP_PAGE_SIZE_BITS) + intersect_start;
      uint8_t* d = data;
      if (d && access_type == ACCESS_NORMAL && !cl->reader->fixed_data_size) {
        d += intersect_start - offset;
      }
      if (!cl->callback(cl->callback_closure, cl->q, cl->reader, tstamp,
                        start, start + intersect_end - intersect_start, access_type, d)) {
        /* empty out the current region of interest */
        bound_abort(cl, num_ranges);
        return 0;
      }
    }
  }

  if (can_cover) {
    if (cl->mode == MODE_FIND_FIRST_COVER) {
      /* Remove discovered range from the list of interesting ranges. This
         is only a best-effort approach, we may not remove the range if it would
         make the resulting region more complex. This means we may get spurious
         results later. */
      CH_DecompressorBitRunRange remove = { offset, length };
      remove_ranges(&remove, 1, ranges, num_ranges);
    }  
    bound_update(cl, tstamp, tstamp, num_ranges);
  }
  return 1;
}

/**
 * Report mmap events that happened at 'tstamp' or later (if direction < 0)
 * or before 'tstamp' (if direction > 0). We're assuming that any mmap
 * effects happen before the regular memory events for a given tstamp.
 */
static int report_mmap_events_upto(PageScanClosure* cl, CH_TStamp tstamp,
                                   int32_t* next_mmap_event,
                                   CH_DecompressorBitRunRange** ranges,
                                   uint32_t* num_ranges,
                                   CH_Semaphore* local_semaphore) {
  int32_t mmap_event;
  uint32_t* map_operations = cl->mmap_operations;
  uint32_t num_map_operations = cl->num_mmap_operations;
  CH_DBAddrMapEntry* events = get_address_map_entries();
  uint64_t offset = cl->page_num << CH_EFFECT_MAP_PAGE_SIZE_BITS;
  
  if (!next_mmap_event)
    return 1;
  
  mmap_event = *next_mmap_event;
  while (mmap_event >= 0 && mmap_event < num_map_operations) {
    CH_DBAddrMapEntry* e = &events[map_operations[mmap_event]];
    /* we assume that any mmap events at a given tstamp happen before
       normal events at that tstamp */
    if (cl->direction > 0 ? e->tstamp <= tstamp : e->tstamp > tstamp) {
      if (e->tstamp >= cl->begin_tstamp && e->tstamp < cl->end_tstamp) {
        /* clip mmap event's range to page */
        uint64_t start = e->address;
        uint64_t end = start + e->length;
        uint32_t length;
        if (start < offset) {
          start = offset;
        }
        if (end > offset + (1 << CH_EFFECT_MAP_PAGE_SIZE_BITS)) {
          length = (uint32_t)(offset + (1 << CH_EFFECT_MAP_PAGE_SIZE_BITS) - start);
        } else {
          length = end - start;
        }
        start -= offset;
        if (is_in_ranges((uint32_t)start, (uint32_t)start + length, *ranges, *num_ranges)) {
          if (local_semaphore) {
            /* wait for asynchronous history entry scans to complete before
               we publish the mmap result, so that things are reported in the
               right order */
            semaphore_wait_for_all_removed(local_semaphore);
          }
          
          if (!report_result(cl, e->tstamp, (uint32_t)start, length,
                             (uint8_t*)&map_operations[mmap_event],
                             ranges, num_ranges, ACCESS_MMAP, !e->contents_unchanged))
            return 0;
        }
      }
    } else {
      break;
    }
    mmap_event += cl->direction;
  }
  *next_mmap_event = mmap_event;
  return 1;
}

static int report_normal_result(PageScanClosure* cl, CH_TStamp tstamp, uint32_t offset,
                                uint32_t length, uint8_t* data,
                                CH_DecompressorBitRunRange** ranges,
                                uint32_t* num_ranges, int32_t* next_mmap_event) {
  /* report any mmap events that should be reported before the current 'normal'
     access */
  if (!report_mmap_events_upto(cl, tstamp, next_mmap_event, ranges, num_ranges, NULL))
    return 0;
    
  return report_result(cl, tstamp, offset, length, data, ranges, num_ranges,
                       ACCESS_NORMAL, 1);
}

static uint32_t fix_item_length(uint16_t len) {
  return len > 0 ? len : 0x10000;
}

typedef struct {
  CH_TStamp tstamp;
  uint32_t  offset;
  uint32_t  length;
  void*     data;
} ResultRecord;

static int compare_results(const void* v1, const void* v2) {
  const ResultRecord* r1 = v1;
  const ResultRecord* r2 = v2;
  return r1->tstamp - r2->tstamp;
}

/**
 * @return a bitmask of the atoms of this item which match the query
 * (if the item has no bunch structure, then bit 0 is set if the item itself
 * matches the query)
 */
static void consider_item(PageScanClosure* cl, CH_TStamp base_tstamp, uint16_t offset,
                          CH_EffectItem* item, uint8_t* data,
                          CH_DecompressorBitRunRange** ranges,
                          uint32_t* num_ranges, int32_t* next_mmap_event) {
  CH_TStamp found_tstamp = 0;
  uint32_t item_length = fix_item_length(item->length);
  
  if (!is_in_ranges(offset, offset + item_length, *ranges, *num_ranges))
    return;
  if (item->atoms.atoms[0].length_increment == 0) {
    /* no substructure; this access item represents just a single event */
    if (!(base_tstamp >= cl->begin_tstamp && base_tstamp < cl->end_tstamp))
      return;
      
    found_tstamp = base_tstamp;
    report_normal_result(cl, base_tstamp, offset, item_length, data, ranges, num_ranges,
                         next_mmap_event);
  } else {
    /* this access item is a bunch of events */
    int i;
    int num_results = 0;
    ResultRecord results[CH_EFFECT_ATOMS];
    for (i = 0; i < CH_EFFECT_ATOMS; ++i) {
      CH_TStamp tstamp = base_tstamp + item->atoms.atoms[i].instruction_index;
      if (tstamp >= cl->begin_tstamp && tstamp < cl->end_tstamp &&
          is_in_ranges(offset, offset + item->atoms.atoms[i].length_increment,
                       *ranges, *num_ranges)) {
        ResultRecord r =
          { tstamp, offset, item->atoms.atoms[i].length_increment, data };
        results[num_results] = r;
        num_results++;
      }
      offset += item->atoms.atoms[i].length_increment;
      if (data && !cl->reader->fixed_data_size) {
        data += item->atoms.atoms[i].length_increment;
      }
    }
    
    qsort(results, num_results, sizeof(ResultRecord), compare_results);
    /* note that none of the result ranges overlap. So in MODE_FIND_FIRST_COVER,
     * it is impossible for reporting one result to modify the ranges in a way
     * that would stop a later result from intersecting with the ranges */
    for (i = cl->direction > 0 ? 0 : num_results - 1; 0 <= i && i < num_results;
         i += cl->direction) {
      found_tstamp = results[i].tstamp;
      if (!report_normal_result(cl, results[i].tstamp, results[i].offset, results[i].length,
                                results[i].data, ranges, num_ranges, next_mmap_event))
        break;
      if (cl->mode == MODE_FIND_FIRST_ANY)
        break;
    }
  }
}

static void page_scan_search_history_entry(PageScanClosure* cl,
    CH_EffectHistoryEntry* e, CH_DecompressorBitRunRange** ranges,
    uint32_t* num_ranges, int32_t* next_mmap_event) {
  uint32_t access_data_len;
  CH_EffectItem* access_data =
    decompression_cache_acquire(e->access_fileloc, e->access_compressed_size,
                                CH_COMPRESSTYPE_DATA, &access_data_len);
  uint8_t* data = NULL;
  if (cl->reader->has_data) {
    data = (uint8_t*)(access_data + e->access_list_count);
  }

  /* now look for actual matching accesses in the access list */
  if (cl->direction > 0) {
    CH_TStamp base_tstamp = e->first_tstamp;
    uint16_t offset = 0;
    uint32_t i;
    for (i = 0; i < e->access_list_count; ++i) {
      base_tstamp += access_data[i].tstamp_offset;
      offset += access_data[i].offset;
      if (base_tstamp + (1 << CH_EFFECT_ATOM_INSTRUCTION_INDEX_BITS) - 1
          >= cl->begin_tstamp) {
        if (base_tstamp >= cl->end_tstamp)
          break;
        consider_item(cl, base_tstamp, offset, &access_data[i], data, ranges,
                      num_ranges, next_mmap_event);
        if (*num_ranges == 0)
          break;
      }
      if (data) {
        if (cl->reader->fixed_data_size) {
          data += cl->reader->fixed_data_size;
        } else {
          data += fix_item_length(access_data[i].length);
        }
      }
    }
  } else {
    CH_TStamp base_tstamp = e->first_tstamp + e->final_tstamp_offset;
    uint16_t offset = e->final_offset;
    if (data) {
      data += e->access_data_count;
    }
    uint32_t i;
    for (i = e->access_list_count; i > 0; --i) {
      if (data) {
        if (cl->reader->fixed_data_size) {
          data -= cl->reader->fixed_data_size;
        } else {
          data -= fix_item_length(access_data[i - 1].length);
        }
      }
      if (base_tstamp < cl->end_tstamp) {
        if (base_tstamp + (1 << CH_EFFECT_ATOM_INSTRUCTION_INDEX_BITS) - 1
            < cl->begin_tstamp)
          break;
        consider_item(cl, base_tstamp, offset, &access_data[i - 1], data, ranges,
                      num_ranges, next_mmap_event);
        if (*num_ranges == 0)
          break;
      }
      base_tstamp -= access_data[i - 1].tstamp_offset;
      offset -= access_data[i - 1].offset;
    }
  }
  decompression_cache_release(e->access_fileloc, access_data);
}

static int is_next_mmap_event_relevant(PageScanClosure* cl,
    CH_EffectHistoryEntry* e, int32_t next_mmap_event) {
  CH_DBAddrMapEntry* events = get_address_map_entries();
  CH_TStamp tstamp;
  if (!(next_mmap_event >= 0 && next_mmap_event < cl->num_mmap_operations))
    return 0;
    
  tstamp = events[cl->mmap_operations[next_mmap_event]].tstamp;
  return tstamp >= e->first_tstamp && tstamp <= e->last_tstamp;
}

typedef struct {
  PageScanClosure*   inner_cl;
  CH_EffectHistoryEntry* e;
  CH_DecompressorBitRunRange* ranges;
  uint32_t                    num_ranges;
  CH_Semaphore*      local_semaphore;
} HistoryEntryScanClosure;

static void history_entry_scan_thread(void* closure) {
  HistoryEntryScanClosure* cl = closure;
  
  page_scan_search_history_entry(cl->inner_cl, cl->e, &cl->ranges, &cl->num_ranges,
                                 NULL);
  semaphore_remove(cl->local_semaphore);
  safe_free(cl->ranges);
  safe_free(cl);
}

static CH_DecompressorBitRunRange* convert_bitmap_to_ranges(uint16_t* bitmap,
    uint32_t* num_ranges, uint32_t count) {
  uint8_t b = 0;
  uint32_t range_count = 0;
  uint32_t i = 0;
  uint32_t offset = 0;
  CH_DecompressorBitRunRange* result;
  uint32_t c = count;
  uint16_t* saved_bitmap = bitmap;
  
  while (c > 0) {
    if (*bitmap) {
      range_count += b;
      c -= *bitmap;
    }
    b ^= 1;
    ++bitmap;
  }

  bitmap = saved_bitmap;
  result = safe_malloc(sizeof(CH_DecompressorBitRunRange)*range_count);
  b = 0;
  while (offset < count) {
    if (b && *bitmap) {
      if (i > 0 && result[i - 1].offset + result[i - 1].length == offset) {
        result[i - 1].length += *bitmap;
      } else {
        result[i].offset = offset;
        result[i].length = *bitmap;
        ++i;
      }
    }
    b ^= 1;
    offset += *bitmap;
    ++bitmap;
  }
  
  *num_ranges = i;
  return safe_realloc(result, i*sizeof(CH_DecompressorBitRunRange));
}

static uint32_t find_first_history_entry(PageScanClosure* cl) {
  uint32_t begin = 0;
  uint32_t end = cl->page_data->db_entry.history_entry_count;
  while (end - begin > 1) {
    uint32_t mid = (begin + end)/2;
    CH_EffectHistoryEntry* e = &cl->page_data->history_entries[mid];
    if (cl->direction > 0
        ? cl->begin_tstamp > e->first_tstamp
        : cl->end_tstamp > e->first_tstamp) {
      begin = mid;
    } else {
      end = mid;
    }
  }
  return cl->direction > 0 ? begin : end - 1;
}

static int32_t find_first_mmap_event(int direction, uint32_t* map_operations,
    uint32_t num_map_operations, CH_TStamp begin_tstamp, CH_TStamp end_tstamp) {
  int32_t next_mmap_event;
  CH_DBAddrMapEntry* events = get_address_map_entries();
  if (direction > 0) {
    /* XXX could use binary search here */
    for (next_mmap_event = 0; next_mmap_event < num_map_operations;
         ++next_mmap_event) {
      if (events[map_operations[next_mmap_event]].tstamp >=
          begin_tstamp)
        break;
    }
  } else {
    /* XXX could use binary search here */
    for (next_mmap_event = num_map_operations - 1; next_mmap_event >= 0;
         --next_mmap_event) {
      if (events[map_operations[next_mmap_event]].tstamp <
          end_tstamp)
        break;
    }
  }
  return next_mmap_event;
}

static void page_scan_thread(void* closure) {
  PageScanClosure* cl = closure;
  int32_t history_entry;
  uint32_t history_entry_count;
  LoadedBitmap cached_bitmap;
  int32_t next_mmap_event;
  CH_Semaphore local_semaphore;
  
  memset(&cached_bitmap, 0, sizeof(LoadedBitmap));
  cached_bitmap.bitmap_entry = -1;

  ensure_entry_lists_loaded(cl->page_data);
  history_entry_count =
    cl->page_data ? cl->page_data->db_entry.history_entry_count : 0;
  
  /* find the relevant history entries */
  history_entry = history_entry_count > 0 ? find_first_history_entry(cl) : 0;
  next_mmap_event = find_first_mmap_event(cl->direction, cl->mmap_operations,
      cl->num_mmap_operations, cl->begin_tstamp, cl->end_tstamp);
  
  if (cl->mode != MODE_FIND_FIRST_ANY) {
    /* asynchronous operations are possible, so init their completion semaphore */
    semaphore_init(&local_semaphore);
  }
  
  bound_update_read_only(cl, &cl->num_ranges);

  while (history_entry >= 0 && history_entry < history_entry_count &&
         cl->num_ranges > 0) {
    CH_EffectHistoryEntry* e = &cl->page_data->history_entries[history_entry];
    uint16_t* bitmap;
    int need_to_recheck_bound;

    if (page_scan_end_of_history(cl, e))
      break;
    
    /* report mmap events up to the start of this history entry */
    if (!report_mmap_events_upto(cl,
          cl->direction > 0 ? e->first_tstamp : e->last_tstamp, &next_mmap_event,
          &cl->ranges, &cl->num_ranges,
          cl->mode == MODE_FIND_FIRST_COVER ? &local_semaphore : NULL))
      break;
    
    /* look in the bitmap to see if there is a potential access */
    bitmap =
      load_bitmap_for_history_entry(cl->page_data, history_entry, &cached_bitmap,
                                    &need_to_recheck_bound);
    if (decompress_check_any_set_in_bit_run_block(bitmap, cl->ranges, cl->num_ranges)) {
      /* there is an applicable access in this history interval. If the history
         interval is entirely in the query time range, then we have a definite
         access match and we can update the bound now. */
      if (e->first_tstamp >= cl->begin_tstamp && e->last_tstamp < cl->end_tstamp) {
        bound_update(cl, e->first_tstamp, e->last_tstamp, &cl->num_ranges);
      } else if (need_to_recheck_bound) {
        bound_update_read_only(cl, &cl->num_ranges);
      }
      
      /* check whether the history entry is still interesting ... someone might
         have found a better match while we were messing with the bitmap */
      if (cl->num_ranges == 0 || page_scan_end_of_history(cl, e))
        break;

      /* We search the page asynchronously if mode is MODE_FIND_ALL. We can also
         search asynchronously if mode is MODE_FIND_FIRST_COVER and the
         history entry is entirely inside our relevant range, because then the
         access bitmap tells us exactly what was touched, so we can update our
         ranges without having to scan the history entry's access list. We
         also require that there be no mmap events in the range, because
         they'd mess us up. */
      if (cl->mode == MODE_FIND_ALL ||
          (cl->mode == MODE_FIND_FIRST_COVER &&
           e->first_tstamp >= cl->begin_tstamp && e->last_tstamp < cl->end_tstamp &&
           !is_next_mmap_event_relevant(cl, e, next_mmap_event))) {
        /* search the page asynchronously */
        /* clone the ranges array for use by the asynchronous thread
           if we're going to alter it later */
        CH_DecompressorBitRunRange* ranges =
            safe_malloc(sizeof(CH_DecompressorBitRunRange)*cl->num_ranges);
        HistoryEntryScanClosure h_cl = { cl, e, ranges, cl->num_ranges, &local_semaphore };
        HistoryEntryScanClosure* h_closure = safe_malloc(sizeof(HistoryEntryScanClosure));
        
        memcpy(ranges, cl->ranges, sizeof(CH_DecompressorBitRunRange)*cl->num_ranges);
        *h_closure = h_cl;
        semaphore_add(&local_semaphore);
        run_on_thread(history_entry_scan_thread, h_closure);

        if (cl->mode == MODE_FIND_FIRST_COVER) {
          /* now we update cl->ranges based on the contents of the bitmap */
          uint32_t bitmap_num_ranges;
          CH_DecompressorBitRunRange* bitmap_ranges = 
            convert_bitmap_to_ranges(bitmap, &bitmap_num_ranges,
                                     1 << CH_EFFECT_MAP_PAGE_SIZE_BITS);
          remove_ranges(bitmap_ranges, bitmap_num_ranges, &cl->ranges, &cl->num_ranges);
          safe_free(bitmap_ranges);
        }
      } else {
        if (cl->mode == MODE_FIND_FIRST_COVER) {
          /* wait for all previous asynchronous operations to complete before
             we do a synchronous one */
          semaphore_wait_for_all_removed(&local_semaphore);
        }
        
        page_scan_search_history_entry(cl, e, &cl->ranges, &cl->num_ranges,
                                       &next_mmap_event);
      }
    }
    
    if (need_to_recheck_bound) {
      bound_update_read_only(cl, &cl->num_ranges);
    }
    
    history_entry += cl->direction;
  }

  if (cl->mode != MODE_FIND_FIRST_ANY) {
    /* asynchronous operations are possible, so wait for all the operations
       to be done */
    semaphore_wait_for_all_removed(&local_semaphore);
    semaphore_destroy(&local_semaphore);
  }

  /* report any lingering mmap events */
  if (cl->num_ranges > 0) {
    report_mmap_events_upto(cl,
      cl->direction > 0 ? cl->end_tstamp : cl->begin_tstamp, &next_mmap_event,
      &cl->ranges, &cl->num_ranges, NULL);
  }
  
  bound_unreference(cl->bound, 0);
  loaded_bitmap_destroy(&cached_bitmap);
  complete_work(cl->q, 1, NULL);
  if (cl->status_semaphore) {
    semaphore_remove(cl->status_semaphore);
  }
  safe_free(cl->mmap_operations);
  safe_free(cl->ranges);
  safe_free(cl);
}

void effect_map_reader_do_scan(CH_EffectMapReader* reader, QueryThread* q,
                               CH_TStamp begin_tstamp, CH_TStamp end_tstamp,
                               CH_Range* ranges, uint32_t num_ranges,
                               CH_EffectScanMode mode, int direction,
                               int abortable,
                               CH_EffectMapReaderScanResultCallback callback,
                               void* callback_closure,
                               CH_Semaphore* completion_semaphore) {
  uint32_t range = 0;
  ScanBound* bound = NULL;
  int abort = 0;

  if (mode == MODE_FIND_FIRST_ANY || abortable) {
    bound = safe_malloc(sizeof(ScanBound));
    pthread_mutex_init(&bound->mutex, NULL);
    if (direction < 0) {
      bound->value = begin_tstamp;
    } else {
      bound->value = end_tstamp;
    }
    bound->ref_count = 1;
    bound->aborted = 0;
  }
  
  while (range < num_ranges) {
    uint64_t page_num = ranges[range].start >> CH_EFFECT_MAP_PAGE_SIZE_BITS;
    uint32_t last_range_in_page = range;
    CH_EffectMapReaderPage* page_data = find_page(reader, page_num);
    uint32_t num_mmap_operations;
    uint32_t* mmap_operations =
      create_memory_map_history_for(page_num << CH_EFFECT_MAP_PAGE_SIZE_BITS,
                                    (page_num + 1) << CH_EFFECT_MAP_PAGE_SIZE_BITS,
                                    &num_mmap_operations);
    CH_Address page_start = page_num << CH_EFFECT_MAP_PAGE_SIZE_BITS;
    CH_Address next_start = (page_num + 1) << CH_EFFECT_MAP_PAGE_SIZE_BITS;
    
    while (last_range_in_page + 1 < num_ranges) {
      uint64_t next_page_num =
        ranges[last_range_in_page + 1].start >> CH_EFFECT_MAP_PAGE_SIZE_BITS;
      if (next_page_num != page_num)
        break;
      ++last_range_in_page;
    }
    
    if (page_data || num_mmap_operations) {
      PageScanClosure closure =
        { page_num, page_data, completion_semaphore, reader, q, begin_tstamp, end_tstamp,
          bound, NULL /* filled in later */, last_range_in_page - range + 1,
          mode, direction, callback, callback_closure, mmap_operations,
          num_mmap_operations };
      uint32_t i;

      closure.ranges = safe_malloc(sizeof(CH_DecompressorBitRunRange)*closure.num_ranges);

      for (i = range; i <= last_range_in_page; ++i) {
        CH_Address len = ranges[i].length;
        CH_Address max_len = next_start - ranges[i].start;
        closure.ranges[i - range].offset = (uint32_t)(ranges[i].start - page_start);
        if (len > max_len) {
          /* this can only happen for the last range in the page */
          len = max_len;
        }
        closure.ranges[i - range].length = (uint32_t)len;
      }
      
      if (completion_semaphore) {
        semaphore_add(completion_semaphore);
      }
      if (bound) {
        pthread_mutex_lock(&bound->mutex);
        ++bound->ref_count;
        pthread_mutex_unlock(&bound->mutex);
      }
      spawn_work(q, page_scan_thread, &closure, sizeof(PageScanClosure), 1);
    }
    
    /* ranges[last_range_in_page] might need to be adjusted if it crosses
       out of the current page */
    if (((ranges[last_range_in_page].start + ranges[last_range_in_page].length - 1)
         >> CH_EFFECT_MAP_PAGE_SIZE_BITS) != page_num) {
      CH_Address new_start = (page_num + 1) << CH_EFFECT_MAP_PAGE_SIZE_BITS;
      ranges[last_range_in_page].length -=
        (new_start - ranges[last_range_in_page].start);
      ranges[last_range_in_page].start = new_start;
      range = last_range_in_page;
    } else {
      /* skip to the next range */
      range = last_range_in_page + 1;
    }         
  }

  bound_unreference(bound, abort);
  safe_free(ranges);
}

int obtain_memory_contents_from_mmap_callback(QueryThread* q,
  CH_Address start_addr, CH_Address end_addr, void* data, void* buf) {
  CH_DBAddrMapEntry* e = &get_address_map_entries()[*(uint32_t*)data];
  uint64_t mapped_area = e->offset + start_addr - e->address;
  uintptr_t len = end_addr - start_addr;
  int OK = 0;

  if (e->contents_from_file) {
    int fd = dbg_aquire_fd_for_mapped_file(e);
    if (fd >= 0) {
      ssize_t r = pread64(fd, buf, len, mapped_area);
      if (r >= 0) {
        if (r < len) {
          /* mmapped data beyond the end-of-file is mapped as zeroes */
          memset((char*)buf + r, 0, len - r);
        }
        OK = 1;
      } else {
        char* name =
          db_read_alloc(get_db(), e->filename_fileloc, e->filename_len);
        debugger_warning(q, "debug.read.mmaped.file.error",
          "Error reading memory mapped file '%.*s' at %llx-%llx",
          e->filename_len, name, (long long)mapped_area, (long long)(mapped_area + len));
        safe_free(name);
      }
      dbg_release_fd_for_mapped_file(e, fd);
    } else {
      char* name = e->filename_fileloc ?
          db_read_alloc(get_db(), e->filename_fileloc, e->filename_len)
        : NULL;
      debugger_warning(q, "debug.read.mmaped.file.not found",
          "Cannot find memory mapped file %s%.*s%sto satisfy read request",
          name ? "'" : "", e->filename_len, name ? name : "", name ? "' " : "");
      safe_free(name);
    }
  } else if (e->contents_set_zero) {
    memset(buf, 0, len);
    OK = 1;
  } else if (e->is_mapped) {
    debugger_warning(q, "debug.read.mapped.unknown.memory",
        "Read of mapped but unknown memory at %llx-%llx",
        (long long)start_addr, (long long)end_addr);
  } else {
    debugger_warning(q, "debug.read.unmapped.memory",
        "Read of unmapped memory at %llx-%llx",
        (long long)start_addr, (long long)end_addr);
  }
  return OK;
}
