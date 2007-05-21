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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "effect_map_write.h"
#include "util.h"
#include "config.h"

#define PTR_BITS (sizeof(void*)*8)

static CH_BunchedEffectAtoms zero_atoms;

static uintptr_t MIN(uintptr_t a, uintptr_t b) {
  return (a <= b) ? a : b;
}

void effect_map_init(CH_EffectMap* map, uint8_t map_num, CH_DBFile* db,
                     uint32_t access_list_length) {
  uintptr_t table_size;

  map->access_list_length = access_list_length;
  map->pages.table_size = 128;
  table_size = sizeof(CH_EffectPageRecord**)*map->pages.table_size;
  map->pages.table = safe_malloc(table_size);
  memset(map->pages.table, 0, table_size);
  map->pages.table_count = 0;
  map->db = db;
  map->map_num = map_num;
  pthread_mutex_init(&map->mutex, NULL);
}

static void reset_record(CH_EffectMap* map, CH_EffectPageRecord* r, CH_TStamp tstamp) {
  r->base_tstamp = tstamp;
  r->last_tstamp = tstamp;
  r->access_list =
    safe_malloc(sizeof(CH_EffectItem)*map->access_list_length);
  r->access_data.data = NULL;
  r->access_data.size = 0;
  r->access_count = 0;
  r->access_data_count = 0;
  memset(r->access_bitmap, 0, 1 << (CH_EFFECT_MAP_PAGE_SIZE_BITS - 3));

  r->history_last_tstamp_offset = 0;
  r->history_last_offset = 0;
}

static CH_EffectPageRecord* create_new_record(CH_EffectMap* map, uintptr_t page_num,
                                              CH_TStamp tstamp) {
  uint32_t access_bitmap_size = 1 << (CH_EFFECT_MAP_PAGE_SIZE_BITS - 3);
  CH_EffectPageRecord* r =
    safe_malloc(sizeof(CH_EffectPageRecord) + access_bitmap_size);
  r->page_num = page_num;
  r->access_bitmap = (uintptr_t*)(r + 1);

  r->history_entries.data = NULL;
  r->history_entries.size = 0;
  r->history_entry_count = 0;

  r->bitmap_entries.data = NULL;
  r->bitmap_entries.size = 0;
  r->bitmap_entry_count = 0;

  compress_init(&r->compressed_bitmap_buf, CH_COMPRESSTYPE_BITRUNS);

  reset_record(map, r, tstamp);
  return r;
}

static CH_EffectPageRecord* get_page_record(CH_EffectMap* map,
                                            uintptr_t page_num,
                                            CH_TStamp tstamp) {
  uint32_t size = map->pages.table_size;
  uint32_t index = hash_page_num(page_num, size);
  CH_EffectPageRecord* r;

  for (;;) {
    CH_EffectPageRecord* rp = map->pages.table[index];
    if (0) printf("pagenum=%p, index=%d\n", (void*)page_num, index);
    if (rp) {
      if (rp->page_num == page_num)
        return rp;
      ++index;
      if (index >= size) {
        index = 0;
      }
    } else {
      break;
    }
  }

  ++map->pages.table_count;

  if (map->pages.table_count*8 >= map->pages.table_size) {
    uint32_t new_size = map->pages.table_size*2;
    CH_EffectPageRecord** new_table =
      safe_malloc(new_size*sizeof(CH_EffectPageRecord*));
    uint32_t i;

    memset(new_table, 0, new_size*sizeof(CH_EffectPageRecord*));
    for (i = 0; i < map->pages.table_size; ++i) {
      CH_EffectPageRecord* rp = map->pages.table[i];
      if (rp) {
        index = hash_page_num(rp->page_num, new_size);
        while (new_table[index]) {
          ++index;
          if (index >= new_size) {
            index = 0;
          }
        }
        new_table[index] = rp;
      }
    }

    safe_free(map->pages.table);
    map->pages.table = new_table;
    map->pages.table_size = new_size;

    return get_page_record(map, page_num, tstamp);
  }

  r = create_new_record(map, page_num, tstamp);
  map->pages.table[index] = r;
  return r;
}

static CH_TStamp get_last_tstamp_offset(CH_TStamp base, CH_EffectItem* item) {
  int max_atom_index = 0;
  int i;
  for (i = 0; i < CH_EFFECT_ATOMS; ++i) {
    uint8_t atom_index = item->atoms.atoms[i].instruction_index;
    if (atom_index > max_atom_index) {
      max_atom_index = atom_index;
    }
  }
  return base + max_atom_index;
}

typedef struct {
  CH_EffectMap* map;
  CH_EffectItem* access_list;
  int access_list_count;
  int access_data_count;
  void* access_data;
  CH_EffectPageRecord* record;
  int hist_index;
} HistoryWriterClosure;

static void history_writer(void* closure) {
  HistoryWriterClosure* cl = closure;
  CH_CompressorState compress;
  CH_EffectHistoryEntry* entry;
  uint64_t offset;

  /* first, compress this stuff */
  compress_init(&compress, CH_COMPRESSTYPE_DATA);
  compress_data(&compress, cl->access_list,
                cl->access_list_count*sizeof(CH_EffectItem));
  safe_free(cl->access_list);
  compress_data(&compress, cl->access_data, cl->access_data_count);
  safe_free(cl->access_data);
  compress_done(&compress);

  /* write it to the database */
  offset = db_append_sync(cl->map->db, compress.output.data,
                          compress.output_len);
  {
    char buf[1024];
    /* RACE CONDITION */
    sprintf(buf, "history%d-%llx-%d", cl->map->map_num,
            (long long)cl->record->page_num, cl->hist_index);
    compress_finish(&compress, buf);
  }

  /* The history_entries array might be moved by the main thread so
     we need to grab the lock */
  pthread_mutex_lock(&cl->map->mutex);
  entry = &((CH_EffectHistoryEntry*)cl->record->history_entries.data)[cl->hist_index];
  entry->access_fileloc = offset;
  entry->access_compressed_size = compress.output_len;
  pthread_mutex_unlock(&cl->map->mutex);

  semaphore_remove(&cl->map->task_semaphore);
  safe_free(cl);
}

typedef struct {
  CH_EffectMap* map;
  void* data;
  uintptr_t len;
  CH_EffectPageRecord* record;
  int bitmap_index;
} BitmapWriterClosure;

static void bitmap_writer(void* closure) {
  BitmapWriterClosure* cl = closure;
  CH_EffectBitmapEntry* entry;
  uint64_t offset;
  
  offset = db_append_sync(cl->map->db, cl->data, cl->len);
  safe_free(cl->data);

  /* The bitmap_entries array might be moved by the main thread so
     we need to grab the lock */
  pthread_mutex_lock(&cl->map->mutex);
  entry = &((CH_EffectBitmapEntry*)cl->record->bitmap_entries.data)[cl->bitmap_index];
  entry->bitmap_fileloc = offset;
  entry->bitmap_compressed_size = cl->len;
  pthread_mutex_unlock(&cl->map->mutex);

  semaphore_remove(&cl->map->task_semaphore);
  safe_free(cl);
}

static void flush_page_record(CH_EffectMap* map, CH_EffectPageRecord* r, int force) {
  uint32_t hist_index = r->history_entry_count++;
  CH_EffectHistoryEntry* hist_entry;

  pthread_mutex_lock(&map->mutex);
  ensure_buffer_size(&r->history_entries,
                     (hist_index + 1)*sizeof(CH_EffectHistoryEntry));
  /* maybe grow the buffer here even though we may not need the extra item
     right now */
  ensure_buffer_size(&r->bitmap_entries,
                     (r->bitmap_entry_count + 1)*sizeof(CH_EffectBitmapEntry));
  pthread_mutex_unlock(&map->mutex);

  hist_entry = &((CH_EffectHistoryEntry*)r->history_entries.data)[hist_index];
  hist_entry->first_tstamp = r->base_tstamp;
  hist_entry->last_tstamp =
    get_last_tstamp_offset(r->last_tstamp, &r->access_list[r->access_count - 1]);
  hist_entry->final_tstamp_offset = r->history_last_tstamp_offset;
  hist_entry->final_offset = r->history_last_offset;
  hist_entry->access_fileloc = (int64_t)-1;
  hist_entry->access_compressed_size = (int64_t)-1;
  hist_entry->access_list_count = r->access_count;
  hist_entry->access_data_count = r->access_data_count;
  hist_entry->access_bitmap_index = r->bitmap_entry_count;
  {
    HistoryWriterClosure cl = { map, r->access_list, r->access_count,
                                r->access_data_count, r->access_data.data,
                                r, hist_index };
    HistoryWriterClosure* clm = safe_malloc(sizeof(HistoryWriterClosure));
    *clm = cl;
    semaphore_add(&map->task_semaphore);
    run_on_thread(history_writer, clm);
  }
  
  /* XXX ASSUMES LITTLE ENDIAN; if big-endian, we should byte-swap the
     access bitmap or change compress_bit_runs */
  compress_bit_runs(&r->compressed_bitmap_buf, r->access_bitmap,
                    (1 << CH_EFFECT_MAP_PAGE_SIZE_BITS)/PTR_BITS);
  if (force ||
      r->compressed_bitmap_buf.output_len >
      CH_TARGET_COMPRESSED_BITMAP_CHUNK_SIZE) {
    compress_done(&r->compressed_bitmap_buf);
    {
      char buf[1024];
      sprintf(buf, "bitmap%d-%llx-%d", map->map_num,
              (long long)r->page_num, r->bitmap_entry_count);
      compress_finish_nofree(&r->compressed_bitmap_buf, buf);
    }
    {
      BitmapWriterClosure cl = { map, r->compressed_bitmap_buf.output.data,
                                 r->compressed_bitmap_buf.output_len, r,
                                 r->bitmap_entry_count };
      BitmapWriterClosure* clm = safe_malloc(sizeof(BitmapWriterClosure));
      *clm = cl;
      ++r->bitmap_entry_count;
      semaphore_add(&map->task_semaphore);
      run_on_thread(bitmap_writer, clm);
    }
    /* reinitialize because the thread has taken ownership of the data,
       so we need a new buffer */
    compress_init(&r->compressed_bitmap_buf, CH_COMPRESSTYPE_BITRUNS);
  }
}

static void reset_page_record(CH_EffectMap* map, CH_EffectPageRecord* r,
                              CH_TStamp tstamp) {
  flush_page_record(map, r, 0);
  reset_record(map, r, tstamp);
}

void effect_map_prefinish(CH_EffectMap* map) {
  uint32_t i;
  for (i = 0; i < map->pages.table_size; ++i) {
    CH_EffectPageRecord* r = map->pages.table[i];
    if (r) {
      /* force the page to flush all its state, including bitmaps */
      flush_page_record(map, r, 1);
    }
  }
}

void effect_map_finish(CH_EffectMap* map, char const* name) {
  uint32_t i;
  uint64_t offset;
  uint32_t page_count = 1;
  CH_EffectPageEntry* page_entries;
  uint32_t* page_table;
  CH_EffectDBMap* db_map;
  uintptr_t total_db_map_size;

  for (i = 0; i < map->pages.table_size; ++i) {
    CH_EffectPageRecord* r = map->pages.table[i];
    if (r) {
      ++page_count;
    }
  }

  /* wait for all asynchronous work to complete */
  semaphore_wait_for_all_removed(&map->task_semaphore);

  total_db_map_size = sizeof(CH_EffectDBMap) + sizeof(CH_EffectPageEntry)*page_count
    + sizeof(uint32_t)*map->pages.table_size;
  db_map = safe_malloc(total_db_map_size);
  db_map->page_entry_count = page_count;
  db_map->page_table_size = map->pages.table_size;

  page_table = (uint32_t*)(db_map + 1);
  page_entries = (CH_EffectPageEntry*)(page_table + map->pages.table_size);
  page_count = 1;
  memset(&page_entries[0], 0, sizeof(page_entries[0]));
  for (i = 0; i < map->pages.table_size; ++i) {
    CH_EffectPageRecord* r = map->pages.table[i];
    if (r) {
      page_entries[page_count].page_num = r->page_num;
      page_entries[page_count].history_entry_fileloc =
        db_append_sync(map->db, r->history_entries.data,
                       r->history_entry_count*sizeof(CH_EffectHistoryEntry));
      safe_free(r->history_entries.data);
      page_entries[page_count].history_entry_count = r->history_entry_count;
      page_entries[page_count].bitmap_entry_fileloc =
        db_append_sync(map->db, r->bitmap_entries.data,
                       r->bitmap_entry_count*sizeof(CH_EffectBitmapEntry));
      safe_free(r->bitmap_entries.data);
      page_entries[page_count].bitmap_entry_count = r->bitmap_entry_count;
      page_table[i] = page_count;
      ++page_count;
      safe_free(r);
    } else {
      page_table[i] = 0;
    }
  }
  safe_free(map->pages.table);

  offset = db_append_sync(map->db, db_map, total_db_map_size);

  db_add_directory_entry(map->db, name, offset, total_db_map_size);
}

static void set_bits(uintptr_t* bits, uint32_t offset,
                     uint32_t length) {
  uint32_t word_start = offset/PTR_BITS;
  uint32_t word_end = (offset + length)/PTR_BITS;
  if (word_start < word_end) {
    uint32_t high_bits = (word_start + 1)*PTR_BITS - offset;
    uint32_t low_bits = (offset + length) - word_end*PTR_BITS;
    int i;

    bits[word_start] |=
      (((uintptr_t)1 << high_bits) - 1) << (PTR_BITS - high_bits);
    for (i = word_start + 1; i < word_end; ++i) {
      bits[i] = (uintptr_t)-1;
    }
    if (low_bits) {
      bits[word_end] |= ((uintptr_t)1 << low_bits) - 1;
    }
  } else {
    bits[word_start] |=
      (((uintptr_t)1 << length) - 1) << (offset - word_start*PTR_BITS);
  }
}

static void append_page(CH_EffectMap* map, CH_TStamp tstamp,
                        uintptr_t page_num, uint16_t offset,
                        uint32_t length, CH_BunchedEffectAtoms* atoms,
                        void* data, uint32_t data_size) {
  CH_EffectPageRecord* r = get_page_record(map, page_num, tstamp);
  uint64_t tstamp_offset = tstamp - r->base_tstamp;
  uint32_t tstamp_offset32 = (uint32_t)tstamp_offset;
  uint32_t access_index = r->access_count;
  CH_EffectItem* item;

  if (tstamp_offset != tstamp_offset32 ||
      access_index + 1 >= map->access_list_length) {
    reset_page_record(map, r, tstamp);
    tstamp_offset = tstamp_offset32 = 0;
    access_index = 0;
  }
  r->last_tstamp = tstamp;
  r->access_count = access_index + 1;
  item = &r->access_list[access_index];
  if (tstamp_offset32 < r->history_last_tstamp_offset) {
    fprintf(stderr, "ERROR: time going backwards\n");
  }
  item->tstamp_offset = tstamp_offset32 - r->history_last_tstamp_offset;
  r->history_last_tstamp_offset = tstamp_offset32;
  item->offset = offset - r->history_last_offset;
  r->history_last_offset = offset;
  item->length = (uint16_t)length;
  item->atoms = *atoms;
  set_bits(r->access_bitmap, offset, length);
  if (data) {
    ensure_buffer_size(&r->access_data, r->access_data_count + data_size);
    memcpy(r->access_data.data + r->access_data_count, data, data_size);
    r->access_data_count += data_size;
  }
}

static void append_page_aligned(CH_EffectMap* map, CH_TStamp tstamp,
                                uintptr_t page_num, uint16_t offset,
                                uint32_t length) {
  CH_EffectPageRecord* r = get_page_record(map, page_num, tstamp);
  uint64_t tstamp_offset = tstamp - r->base_tstamp;
  uint32_t tstamp_offset32 = (uint32_t)tstamp_offset;
  uint32_t access_index = r->access_count;
  CH_EffectItem* item;

  if (tstamp_offset != tstamp_offset32 ||
      access_index + 1 >= map->access_list_length) {
    reset_page_record(map, r, tstamp);
    tstamp_offset = tstamp_offset32 = 0;
    access_index = 0;
  }
  r->last_tstamp = tstamp;
  r->access_count = access_index + 1;
  item = &r->access_list[access_index];
  if (tstamp_offset32 < r->history_last_tstamp_offset) {
    fprintf(stderr, "ERROR: time going backwards\n");
  }
  item->tstamp_offset = tstamp_offset32 - r->history_last_tstamp_offset;
  r->history_last_tstamp_offset = tstamp_offset32;
  item->offset = offset - r->history_last_offset;
  r->history_last_offset = offset;
  item->length = (uint16_t)length;
  item->atoms = zero_atoms;
  item->atoms.atoms[0].instruction_index = 0;
  item->atoms.atoms[0].length_increment = length;
  r->access_bitmap[offset/PTR_BITS] |=
    (((uintptr_t)1 << length) - 1) << (offset & (PTR_BITS-1));
}

static void append_page_aligned_isodata(CH_EffectMap* map, CH_TStamp tstamp,
                                        uintptr_t page_num, uint16_t offset,
                                        uint32_t length, void* data) {
  CH_EffectPageRecord* r = get_page_record(map, page_num, tstamp);
  uint64_t tstamp_offset = tstamp - r->base_tstamp;
  uint32_t tstamp_offset32 = (uint32_t)tstamp_offset;
  uint32_t access_index = r->access_count;
  CH_EffectItem* item;

  if (tstamp_offset != tstamp_offset32 ||
      access_index + 1 >= map->access_list_length) {
    reset_page_record(map, r, tstamp);
    tstamp_offset = tstamp_offset32 = 0;
    access_index = 0;
  }
  r->last_tstamp = tstamp;
  r->access_count = access_index + 1;
  item = &r->access_list[access_index];
  if (tstamp_offset32 < r->history_last_tstamp_offset) {
    fprintf(stderr, "ERROR: time going backwards\n");
  }
  item->tstamp_offset = tstamp_offset32 - r->history_last_tstamp_offset;
  r->history_last_tstamp_offset = tstamp_offset32;
  item->offset = offset - r->history_last_offset;
  r->history_last_offset = offset;
  item->length = (uint16_t)length; 
  item->atoms = zero_atoms;
  item->atoms.atoms[0].instruction_index = 0;
  item->atoms.atoms[0].length_increment = length;
  r->access_bitmap[offset/PTR_BITS] |=
    (((uintptr_t)1 << length) - 1) << (offset & (PTR_BITS-1));

  ensure_buffer_size(&r->access_data, r->access_data_count + length);
  memcpy(r->access_data.data + r->access_data_count, data, length);
  r->access_data_count += length;
}

static int is_simple_aligned(uintptr_t addr, uintptr_t length,
                             CH_BunchedEffectAtoms* atoms) {
  return atoms->atoms[1].length_increment == 0 &&
    atoms->atoms[0].length_increment > 0 &&
    (length & (length - 1)) == 0 && (addr & (length - 1)) == 0 &&
    length <= PTR_BITS;
}

/* This obeys the invariant that scissoring zero_atoms always produces
   two zero_atoms. */
static void scissor_atoms(CH_BunchedEffectAtoms* atoms,
                          CH_BunchedEffectAtoms* bottom_atoms,
                          CH_BunchedEffectAtoms* top_atoms,
                          uint32_t amount) {
  int i, j = 0;
  int offset = 0;
  for (i = 0; i < CH_EFFECT_ATOMS; ++i) {
    uint8_t l = atoms->atoms[i].length_increment;
    if (offset + l <= amount) {
      bottom_atoms->atoms[i] = atoms->atoms[i];
    } else if (offset < amount) {
      bottom_atoms->atoms[i].length_increment = amount - offset;
      top_atoms->atoms[0].length_increment = offset + l - amount;
      top_atoms->atoms[0].instruction_index = atoms->atoms[i].instruction_index;
      j = 1;
    } else {
      top_atoms->atoms[j] = atoms->atoms[i];
      bottom_atoms->atoms[i].length_increment = 0;
      bottom_atoms->atoms[i].instruction_index = 0;
      ++j;
    }
  }
  for (; j < CH_EFFECT_ATOMS; ++j) {
    top_atoms->atoms[j].length_increment = 0;
    top_atoms->atoms[j].instruction_index = 0;
  }
}

void effect_map_append(CH_EffectMap* map, CH_TStamp tstamp,
                       uintptr_t addr, uintptr_t length,
                       CH_BunchedEffectAtoms atoms) {
  CH_BunchedEffectAtoms scratch_atoms;
  CH_BunchedEffectAtoms* atom_ptr = &atoms;

  /* check for length = power-of-2 and addr is aligned with length
     and the mask fits in a uintptr_t  */
  /* XXX not currently used but I don't recall why */
  if (0 && is_simple_aligned(addr, length, &atoms)) {
    append_page_aligned(map, tstamp, addr >> CH_EFFECT_MAP_PAGE_SIZE_BITS,
                        (uint16_t)(addr & ((1 << CH_EFFECT_MAP_PAGE_SIZE_BITS) - 1)),
                        (uint32_t)length);
    return;
  }

  while (length > 0) {
    uintptr_t page_num = addr >> CH_EFFECT_MAP_PAGE_SIZE_BITS;
    uint32_t offset = (uint32_t)addr & ((1 << CH_EFFECT_MAP_PAGE_SIZE_BITS) - 1);
    uint32_t amount = (uint32_t)MIN((1 << CH_EFFECT_MAP_PAGE_SIZE_BITS) - offset,
                                    length);
    CH_BunchedEffectAtoms* page_atoms = atom_ptr;
    CH_BunchedEffectAtoms page_atom_scratch;
    if (amount != length) {
      scissor_atoms(atom_ptr, &page_atom_scratch, &scratch_atoms, amount);
      page_atoms = &page_atom_scratch;
      atom_ptr = &scratch_atoms;
    }
    append_page(map, tstamp, page_num, offset, amount, page_atoms, NULL, 0);
    addr += amount;
    length -= amount;
  }
}

void effect_map_append_isodata(CH_EffectMap* map, CH_TStamp tstamp,
                               uintptr_t addr, uintptr_t length,
                               CH_BunchedEffectAtoms atoms,
                               void* data) {
  CH_BunchedEffectAtoms scratch_atoms;
  CH_BunchedEffectAtoms* atom_ptr = &atoms;

  /* check for length = power-of-2 and addr is aligned with length
     and the mask fits in a uintptr_t  */
  /* XXX not currently used but I don't recall why */
  if (0 && is_simple_aligned(addr, length, &atoms)) {
    append_page_aligned_isodata(map, tstamp, addr >> CH_EFFECT_MAP_PAGE_SIZE_BITS,
                                (uint16_t)(addr & ((1 << CH_EFFECT_MAP_PAGE_SIZE_BITS) - 1)),
                                (uint32_t)length, data);
    return;
  }

  while (length > 0) {
    uintptr_t page_num = addr >> CH_EFFECT_MAP_PAGE_SIZE_BITS;
    uint32_t offset = (uint32_t)addr & ((1 << CH_EFFECT_MAP_PAGE_SIZE_BITS) - 1);
    uint32_t amount = (uint32_t)MIN((1 << CH_EFFECT_MAP_PAGE_SIZE_BITS) - offset,
                                    length);
    CH_BunchedEffectAtoms* page_atoms = atom_ptr;
    CH_BunchedEffectAtoms page_atom_scratch;
    if (amount != length) {
      scissor_atoms(atom_ptr, &page_atom_scratch, &scratch_atoms, amount);
      page_atoms = &page_atom_scratch;
      atom_ptr = &scratch_atoms;
    }
    append_page(map, tstamp, page_num, (uint16_t)offset, amount,
                page_atoms, data, amount);
    addr += amount;
    length -= amount;
    data += amount;
  }
}

void effect_map_append_tag(CH_EffectMap* map, CH_TStamp tstamp,
                           uintptr_t addr, uintptr_t length,
                           void* data, uintptr_t data_size) {
  while (length > 0) {
    uintptr_t page_num = addr >> CH_EFFECT_MAP_PAGE_SIZE_BITS;
    uint32_t offset = (uint32_t)addr & ((1 << CH_EFFECT_MAP_PAGE_SIZE_BITS) - 1);
    uint32_t amount = (uint32_t)MIN((1 << CH_EFFECT_MAP_PAGE_SIZE_BITS) - offset,
                                    length);
    append_page(map, tstamp, page_num, offset, amount,
                &zero_atoms, data, data_size);
    addr += amount;
    length -= amount;
  }
}
