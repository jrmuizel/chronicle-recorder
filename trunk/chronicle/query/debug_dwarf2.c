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

#include "debug_dwarf2.h"
#include "debug_internals.h"
#include "debug_dwarf2_constants.h"

#include <libelf/gelf.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  uint64_t           max_abbrev_code;
  CH_DbgDwarf2Offset abbrev_set_offset;
  uint32_t*          abbrev_offsets_by_code;
  const char**       file_names;
  uint32_t           file_count;
} AbbrevOffsets;

typedef struct {
  CH_Address         start;
  CH_Address         end;
  CH_DbgDwarf2Offset compilation_unit;
} ARangeEntry;

struct _CH_DbgDwarf2Object {
  char*               name;
  Elf*                elf;
  Elf_Data*           debug_info_data;
  Elf_Data*           debug_abbrev_data;
  Elf_Data*           debug_aranges_data;
  Elf_Data*           debug_ranges_data;
  Elf_Data*           debug_str_data;
  Elf_Data*           debug_loc_data;
  Elf_Data*           debug_line_data;
  int                 fd;
  uint32_t            elf_machine_type;
  uint32_t            elf_ABI;
  
  uint32_t            num_abbrev_offset_sets;
  AbbrevOffsets*      abbrev_offsets;
  int32_t             num_compilation_units;
  CH_DbgDwarf2Offset* debuginfo_compilation_unit_offsets;
  const char*         globals_text;

  /* lazily constructed map of the object file space. Each entry refers
     to a function or variable. The entries are in increasing 'start' order.
     Entries do not overlap.
   */
  pthread_mutex_t     arange_lock;
  int32_t             num_aranges;
  ARangeEntry*        aranges;
};

/* notify that there's some problem with the debug info */
static void dwarf2_invalid_warning(CH_DbgDwarf2Object* obj,
                                   const char* format, ...) {
  va_list args;
  char buf[10240];

  snprintf(buf, sizeof(buf), "DWARF2 format error in file %s: %s", obj->name, format);
  buf[sizeof(buf) - 1] = 0;

  va_start(args, format);
  debugger_warning_v(NULL, "dwarf2.invalid.warning", buf, args);
  va_end(args);
}

/* BEGIN ACCESSOR FUNCTIONS
   These assume unaligned reads are OK, which is true on x86/x86-64. They
   could be improved to avoid machine unaligned reads.
   All can be called on any thread and are read-only.
*/

static int skip_bytes(CH_DbgDwarf2Object* obj, uint8_t** ptr, uint8_t* end,
                      CH_DbgDwarf2Offset bytes)
{ 
  if (*ptr + bytes > end) {
    dwarf2_invalid_warning(obj, "underrun in skip_bytes"); 
    return 0;
  }
  *ptr += bytes;
  return 1;
}

static int align_bytes(CH_DbgDwarf2Object* obj, uint8_t** ptr, uint8_t* end,
                       int alignment)
{
  uintptr_t v = (uintptr_t)*ptr;
  uintptr_t align_mask = alignment - 1;
  return skip_bytes(obj, ptr, end, align_mask - ((v + align_mask)&align_mask));
}

#define DEFINE_READ(T) \
static int read_##T(CH_DbgDwarf2Object* obj, uint8_t** ptr, uint8_t* end, T* result) \
{ if (*ptr + sizeof(T) > end) { dwarf2_invalid_warning(obj, "underrun in read_"#T); return 0; } \
  *result = *(T*)(*ptr); *ptr += sizeof(T); return 1; }

DEFINE_READ(int8_t)
DEFINE_READ(uint8_t)
DEFINE_READ(uint16_t)
DEFINE_READ(uint32_t)
DEFINE_READ(uint64_t)

#define DEFINE_SKIP(T) \
static int skip_##T(CH_DbgDwarf2Object* obj, uint8_t** ptr, uint8_t* end) \
{ if (*ptr + sizeof(T) > end) { dwarf2_invalid_warning(obj, "underrun in skip_"#T); return 0; } \
  *ptr += sizeof(T); return 1; }

DEFINE_SKIP(uint8_t)
DEFINE_SKIP(uint16_t)
DEFINE_SKIP(uint32_t)
DEFINE_SKIP(uint64_t)

static int read_initial_length(CH_DbgDwarf2Object* obj,
    uint8_t** ptr, uint8_t* end, CH_DbgDwarf2Offset* result, int* is_64bit) {
  uint32_t l32;
  if (!read_uint32_t(obj, ptr, end, &l32))
    return 0;
  if (l32 != 0xFFFFFFFF) {
    *result = l32;
    *is_64bit = 0;
    return 1;
  }
  if (sizeof(CH_DbgDwarf2Offset) != sizeof(uint64_t)) {
    dwarf2_invalid_warning(obj, "Encountered 64-bit length on a 32-bit platform");
    return 0;
  }
  *is_64bit = 1;
  return read_uint64_t(obj, ptr, end, (uint64_t*)result);
}

static int read_uword(CH_DbgDwarf2Object* obj,
                      uint8_t** ptr, uint8_t* end, uint64_t* result,
                      int is_64bit) {
  uint32_t w32;
  if (is_64bit)
    return read_uint64_t(obj, ptr, end, result);
  
  if (!read_uint32_t(obj, ptr, end, &w32))
    return 0;
  *result = w32;
  return 1;
}
static int skip_word(CH_DbgDwarf2Object* obj,
                     uint8_t** ptr, uint8_t* end, int is_64bit) {
  if (is_64bit) {
    return skip_uint64_t(obj, ptr, end);
  } else {
    return skip_uint32_t(obj, ptr, end);
  }
}

static int read_offset(CH_DbgDwarf2Object* obj,
                     uint8_t** ptr, uint8_t* end, CH_DbgDwarf2Offset* result,
                     int is_64bit) {
  uint32_t w32;
  if (is_64bit) {
    if (sizeof(CH_DbgDwarf2Offset) != sizeof(uint64_t)) {
      dwarf2_invalid_warning(obj, "Trying to process 64-bit file on a 32-bit platform");
      return 0;
    }
    return read_uint64_t(obj, ptr, end, (uint64_t*)result);
  }
  
  if (!read_uint32_t(obj, ptr, end, &w32))
    return 0;
  *result = w32;
  return 1;
}

static const char* read_ASCIIZ(CH_DbgDwarf2Object* obj,
                               uint8_t** ptr, uint8_t* end) {
  uint8_t* p = *ptr;
  const char* str = (const char*)p;
  for (;;) {
    if (p >= end) {
      dwarf2_invalid_warning(obj, "underrun in read_ASCIIZ");
      return 0;
    }
    if (!*p) {
      *ptr = p + 1;
      return str;
    }
    p++;
  }
}

static int skip_ASCIIZ(CH_DbgDwarf2Object* obj,
                       uint8_t** ptr, uint8_t* end) {
  return read_ASCIIZ(obj, ptr, end) != NULL;
}

static int read_LEB128_internal(CH_DbgDwarf2Object* obj,
                                uint8_t** ptr, uint8_t* end, int64_t* result,
                                int is_signed) {
  int64_t val = 0;
  int bits = 0;
  uint8_t* p = *ptr;
  for (;;) {
    uint8_t c;
    if (p >= end) {
      dwarf2_invalid_warning(obj, "underrun reading LEB128");
      return 0;
    }
    c = *p;
    p++;
    if (bits >= 63) {
      dwarf2_invalid_warning(obj, "LEB128 overflows 64 bits");
      return 0;
    }
    val |= (c & 0x7F) << bits;
    bits += 7;
    if (!(c & 0x80)) {
      if (is_signed && (c & 0x40)) {
        /* number is negative */
        val |= ~((1 << bits) - 1);
      }
      *result = val;
      *ptr = p;
      return 1;
    }
  }
}
static int read_uLEB128(CH_DbgDwarf2Object* obj,
                        uint8_t** ptr, uint8_t* end, uint64_t* result) {
  int64_t v;
  if (!read_LEB128_internal(obj, ptr, end, &v, 0))
    return 0;
  *result = v;
  return 1;
}
static int read_LEB128(CH_DbgDwarf2Object* obj,
                       uint8_t** ptr, uint8_t* end, int64_t* result) {
  return read_LEB128_internal(obj, ptr, end, result, 1);
}
static int skip_LEB128(CH_DbgDwarf2Object* obj,
                       uint8_t** ptr, uint8_t* end) {
  uint8_t* p = *ptr;
  for (;;) {
    if (p >= end) {
      dwarf2_invalid_warning(obj, "underrun skipping LEB128");
      return 0;
    }
    if (!(*p & 0x80)) {
      *ptr = p + 1;
      return 1;
    }
    p++;
  }
}
/* END OF ACCESSOR FUNCTIONS */

/* Can be called on any thread; readonly */
static AbbrevOffsets* find_set_for(CH_DbgDwarf2Object* obj,
                                   CH_DbgDwarf2Offset abbrev_cu_offset) {
  uint32_t start = 0;
  uint32_t end = obj->num_abbrev_offset_sets;
  /* find the last offset <= abbrev_cu_offset */
  while (start + 2 <= end) {
    uint32_t mid = (start + end)/2;
    if (obj->abbrev_offsets[mid].abbrev_set_offset > abbrev_cu_offset) {
      end = mid;
    } else {
      start = mid;
    }
  }
  if (start == end)
    return NULL;
  return &obj->abbrev_offsets[start];
}

/* Can be called on any thread; readonly */
static int find_abbrev(CH_DbgDwarf2Object* obj, AbbrevOffsets* abbrev_offsets,
                       uint64_t abbrev_code,
                       uint8_t** abbrev_ptr, uint8_t** abbrev_end) {
  if (abbrev_offsets->max_abbrev_code < abbrev_code ||
      !abbrev_offsets->abbrev_offsets_by_code[abbrev_code]) {
    dwarf2_invalid_warning(obj, "Abbrev code %lld not found",
                           (long long)abbrev_code);
    return 0;
  }
  *abbrev_ptr = (uint8_t*)obj->debug_abbrev_data->d_buf +
      abbrev_offsets->abbrev_set_offset +
      abbrev_offsets->abbrev_offsets_by_code[abbrev_code];
  *abbrev_end = (uint8_t*)obj->debug_abbrev_data->d_buf + 
      obj->debug_abbrev_data->d_size;
  return *abbrev_ptr < *abbrev_end;
}

typedef struct {
  uint64_t            base_address;
  CH_DbgDwarf2Object* obj;
  AbbrevOffsets*      abbrev_offsets;
  CH_DbgDwarf2Offset  cu_offset;
  CH_DbgDwarf2Offset  first_entry;
  CH_DbgDwarf2Offset  entries_end;
  int                 is_info_64bit;
  int                 is_address_64bit;
} CompilationUnitReader;

typedef struct {
  CompilationUnitReader* cu_reader;
  uint8_t*               abbrev_ptr;
  uint8_t*               abbrev_end;
  uint8_t*               entry_ptr;
  uint8_t*               entry_end;
  CH_Dwarf2_DW_TAG       tag;
  uint8_t                has_children;
  uint8_t                is_empty;
} EntryReader;

static uint8_t* get_debuginfo_base(CH_DbgDwarf2Object* obj) {
  return (uint8_t*)obj->debug_info_data->d_buf;
}

/* Can be called on any thread; readonly */
static int begin_reading_entry(CompilationUnitReader* cu_reader,
    CH_DbgDwarf2Offset info_offset, EntryReader* reader) {
  CH_DbgDwarf2Object* obj = cu_reader->obj;
  uint8_t* base = get_debuginfo_base(cu_reader->obj);
  uint8_t* ptr = base + info_offset;
  uint8_t* end = base + cu_reader->entries_end;
  uint64_t abbrev_code;
  uint64_t tag;
  
  if (!read_uLEB128(obj, &ptr, end, &abbrev_code))
    return 0;

  reader->cu_reader = cu_reader;
  reader->entry_ptr = ptr;
  reader->entry_end = end;

  if (abbrev_code == 0) {
    reader->is_empty = 1;
    return 1;
  }
  
  reader->is_empty = 0;
  if (!find_abbrev(obj, cu_reader->abbrev_offsets, abbrev_code,
                   &reader->abbrev_ptr, &reader->abbrev_end))
    return 0;
  if (!read_uLEB128(obj, &reader->abbrev_ptr, reader->abbrev_end, &tag))
    return 0;
  if (tag > DW_TAG_MAX) {
    dwarf2_invalid_warning(obj, "Invalid tag %ulld", (unsigned long long)tag);
    return 0;
  }
  reader->tag = (CH_Dwarf2_DW_TAG)tag;
  if (!read_uint8_t(obj, &reader->abbrev_ptr, reader->abbrev_end, &reader->has_children))
    return 0;
  return 1;
}

static int read_address_size(CH_DbgDwarf2Object* obj, uint8_t** ptr, uint8_t* end,
                             int* is_address_64bit) {
  uint8_t address_size;
  if (!read_uint8_t(obj, ptr, end, &address_size))
    return 0;
  if (address_size != 4 && address_size != 8) {
    dwarf2_invalid_warning(obj, "Bad address size %d, expected 4 or 8",
                           address_size);
    return 0;
  }
  *is_address_64bit = address_size == 8;
  return 1;
}

/* Can be called on any thread; readonly */
static int read_debug_info_header(CH_DbgDwarf2Object* obj,
    CH_DbgDwarf2Offset info_cu_offset, CompilationUnitReader* reader) {
  uint8_t* base = get_debuginfo_base(obj);
  uint8_t* ptr = base + info_cu_offset;
  uint8_t* end = base + obj->debug_info_data->d_size;
  uint16_t version;
  CH_DbgDwarf2Offset len;
  CH_DbgDwarf2Offset abbrev_cu_offset;
  if (!read_initial_length(obj, &ptr, end, &len, &reader->is_info_64bit))
    return 0;
  if (ptr + len > end) {
    dwarf2_invalid_warning(obj, "Overrunning debuginfo data");
    return 0;
  }
  reader->entries_end = ptr + len - base;
  if (!read_uint16_t(obj, &ptr, end, &version))
    return 0;
  if (version != 2 && version != 3) {
    dwarf2_invalid_warning(obj, "Unknown debuginfo version %d", version);
    return 0;
  }
  if (!read_offset(obj, &ptr, end, &abbrev_cu_offset, reader->is_info_64bit))
    return 0;
  if (!read_address_size(obj, &ptr, end, &reader->is_address_64bit))
    return 0;

  reader->abbrev_offsets = find_set_for(obj, abbrev_cu_offset);
  if (!reader->abbrev_offsets) {
    dwarf2_invalid_warning(obj, "Abbrev offset not found");
    return 0;
  }
  
  reader->base_address = (uint64_t)-1;
  reader->cu_offset = info_cu_offset;
  reader->obj = obj;
  reader->first_entry = ptr - get_debuginfo_base(obj);
  return 1;
}

static void find_section(CH_DbgDwarf2Object* obj, const char* name, Elf_Scn* section,
                         const char* find_name, Elf_Data** find_data) {
  Elf_Data* data;
  if (strcmp(name, find_name) != 0)
    return;
  data = elf_getdata(section, NULL);
  if (!data || !data->d_buf)
    return;
  if (elf_getdata(section, data)) {
    dwarf2_invalid_warning(obj, "Split data for section %s, ignoring", name);
    return;
  }
  if (*find_data) {
    dwarf2_invalid_warning(obj, "Multiple sections %s, ignoring subsequent", name);
    return;
  }
  *find_data = data;
}

static void free_offset_sets(AbbrevOffsets* offsets, uint32_t count) {
  uint32_t i;
  for (i = 0; i < count; ++i) {
    safe_free(offsets[i].abbrev_offsets_by_code);
  }
  safe_free(offsets);
}

static int build_abbrev_offsets(CH_DbgDwarf2Object* obj) {
  CH_GrowBuf offset_sets;
  uint32_t num_sets = 0;
  uint8_t* ptr = obj->debug_abbrev_data->d_buf;
  uint8_t* base = ptr;
  uint8_t* end = ptr + obj->debug_abbrev_data->d_size;
  init_buf(&offset_sets);
  
  while (ptr < end) {
    CH_GrowBuf current_set;
    uint64_t max_code = 0;
    CH_DbgDwarf2Offset set_offset = ptr - base;
    uint32_t* offsets = NULL;
    AbbrevOffsets* abbrev_offsets;
    init_buf(&current_set);
    
    for (;;) {
      uint64_t next_code;
      uint64_t i;
      CH_DbgDwarf2Offset delta;
      if (!read_uLEB128(obj, &ptr, end, &next_code)) {
        safe_free(current_set.data);
        free_offset_sets((AbbrevOffsets*)offset_sets.data, num_sets);
        return 0;
      }
      if (!next_code)
        break;
      if (next_code > max_code) {
        ensure_buffer_size(&current_set, sizeof(uint32_t)*(next_code + 1));
        offsets = (uint32_t*)current_set.data;
        for (i = max_code + 1; i < next_code; ++i) {
          offsets[i] = 0;
        }
        max_code = next_code;
      }
      delta = ptr - base - set_offset;
      if (delta > (uint32_t)-1) {
        dwarf2_invalid_warning(obj, "Overflow in abbrev lookup tables");
        safe_free(current_set.data);
        free_offset_sets((AbbrevOffsets*)offset_sets.data, num_sets);
        return 0;
      }
      offsets[next_code] = (uint32_t)delta;
      
      if (!skip_LEB128(obj, &ptr, end) ||
          !skip_uint8_t(obj, &ptr, end)) {
        safe_free(current_set.data);
        free_offset_sets((AbbrevOffsets*)offset_sets.data, num_sets);
        return 0;
      }
      for (;;) {
        /* skip attribute definitions */
        uint64_t attribute_name;
        uint64_t attribute_form;
        if (!read_uLEB128(obj, &ptr, end, &attribute_name) ||
            !read_uLEB128(obj, &ptr, end, &attribute_form)) {
          safe_free(current_set.data);
          free_offset_sets((AbbrevOffsets*)offset_sets.data, num_sets);
          return 0;
        }
        if (!attribute_name && !attribute_form)
          break;
      }
    }
    
    ensure_buffer_size(&offset_sets, sizeof(AbbrevOffsets)*(num_sets + 1));
    abbrev_offsets = (AbbrevOffsets*)offset_sets.data + num_sets;
    abbrev_offsets->abbrev_offsets_by_code =
        safe_realloc(current_set.data, sizeof(uint32_t)*(max_code + 1));
    abbrev_offsets->abbrev_set_offset = set_offset;
    abbrev_offsets->max_abbrev_code = max_code;
    abbrev_offsets->file_count = 0;
    abbrev_offsets->file_names = NULL;
    num_sets++;
  }
  
  obj->abbrev_offsets =
      safe_realloc(offset_sets.data, sizeof(AbbrevOffsets)*num_sets);
  obj->num_abbrev_offset_sets = num_sets;
  return 1;
}

static int build_cu_offsets(CH_DbgDwarf2Object* obj) {
  CH_GrowBuf offsets;
  uint8_t* ptr = obj->debug_info_data->d_buf;
  uint8_t* base = ptr;
  uint8_t* end = ptr + obj->debug_info_data->d_size;
  uint32_t count = 0;
  
  init_buf(&offsets);
  while (ptr < end) {
    CH_DbgDwarf2Offset len;
    int is_64bit;

    ++count;
    ensure_buffer_size(&offsets, sizeof(CH_DbgDwarf2Offset)*count);
    ((CH_DbgDwarf2Offset*)offsets.data)[count - 1] = ptr - base;
    if (!read_initial_length(obj, &ptr, end, &len, &is_64bit)) {
      safe_free(offsets.data);
      return 0;
    }
    ptr += len;
  }
  obj->debuginfo_compilation_unit_offsets =
    safe_realloc(offsets.data, sizeof(CH_DbgDwarf2Offset)*count);
  obj->num_compilation_units = count;
  return 1;
}
                         
CH_DbgDwarf2Object* dwarf2_load(int fd, const char* name) {
  Elf_Scn* section;
  GElf_Ehdr global_header;
  CH_DbgDwarf2Object* result;
  
  result = safe_malloc(sizeof(CH_DbgDwarf2Object));
  result->name = safe_strdup(name);
  result->elf = NULL;
  result->debug_abbrev_data = NULL;
  result->debug_info_data = NULL;
  result->debug_ranges_data = NULL;
  result->debug_aranges_data = NULL;
  result->debug_str_data = NULL;
  result->debug_loc_data = NULL;
  result->debug_line_data = NULL;
  result->fd = fd;
  result->abbrev_offsets = NULL;
  result->num_abbrev_offset_sets = 0;
  result->debuginfo_compilation_unit_offsets = NULL;
  result->num_compilation_units = 0;
  result->globals_text = NULL;
  pthread_mutex_init(&result->arange_lock, NULL);
  result->aranges = NULL;
  result->num_aranges = -1;

  if (elf_version(EV_CURRENT) == EV_NONE) {
    dwarf2_close(result);
    return NULL;
  }
  result->elf = elf_begin(fd, ELF_C_READ, NULL);
  if (result->elf == NULL) {
    dwarf2_close(result);
    return NULL;
  }
  if (elf_kind(result->elf) != ELF_K_ELF ||
      gelf_getehdr(result->elf, &global_header) == NULL) {
    dwarf2_close(result);
    return NULL;
  }

  result->elf_ABI = global_header.e_ident[EI_OSABI];
  result->elf_machine_type = global_header.e_machine;

  /* XXX check endianness! */

  section = 0;
  while ((section = elf_nextscn(result->elf, section)) != 0) {
    GElf_Shdr header;
    if (gelf_getshdr(section, &header) != NULL) {
      const char* name = elf_strptr(result->elf, global_header.e_shstrndx,
                                    (size_t)header.sh_name);
      if (name) {
        find_section(result, name, section, ".debug_info", &result->debug_info_data);
        find_section(result, name, section, ".debug_abbrev", &result->debug_abbrev_data);
        find_section(result, name, section, ".debug_aranges", &result->debug_aranges_data);
        find_section(result, name, section, ".debug_ranges", &result->debug_ranges_data);
        find_section(result, name, section, ".debug_str", &result->debug_str_data);
        find_section(result, name, section, ".debug_loc", &result->debug_loc_data);
        find_section(result, name, section, ".debug_line", &result->debug_line_data);
      }
    }
  }

  if (!result->debug_info_data || !result->debug_abbrev_data ||
      !build_abbrev_offsets(result) || !build_cu_offsets(result)) {
    dwarf2_close(result);
    return NULL;
  }
  
  return result;
}

void dwarf2_close(CH_DbgDwarf2Object* obj) {
  safe_free(obj->aranges);
  pthread_mutex_destroy(&obj->arange_lock);
  safe_free(obj->name);
  if (obj->elf) {
    elf_end(obj->elf);
  }
  close(obj->fd);
  free_offset_sets(obj->abbrev_offsets, obj->num_abbrev_offset_sets);
  safe_free(obj->debuginfo_compilation_unit_offsets);
  safe_free(obj);
}

static int translate_dwarf_address_to_file_offset(CH_DbgDwarf2Object* obj,
    uint64_t offset, CH_Address* address) {
  int index = 0;
  GElf_Phdr phdr;
  while (gelf_getphdr(obj->elf, index, &phdr)) {
    if (phdr.p_vaddr <= offset && offset < phdr.p_vaddr + phdr.p_memsz) {
      *address = (CH_Address)(offset - phdr.p_vaddr + phdr.p_offset);
      return 1;
    }
    ++index;
  }
  return 0;
}

static int translate_file_offset_to_dwarf_address(CH_DbgDwarf2Object* obj,
    CH_Address file_offset, uint64_t* dwarf_address) {
  int index = 0;
  GElf_Phdr phdr;
  while (gelf_getphdr(obj->elf, index, &phdr)) {
    if (phdr.p_offset <= file_offset && file_offset < phdr.p_offset + phdr.p_memsz) {
      *dwarf_address = file_offset - phdr.p_offset + phdr.p_vaddr;
      return 1;
    }
    ++index;
  }
  return 0;
}

static int skip_form(CH_DbgDwarf2Object* obj,
                     uint8_t** ptr, uint8_t* end, CH_Dwarf2_DW_FORM form,
                     int is_address_64bit, int is_info_64bit) {
  switch (form) {
    case DW_FORM_addr:
      return skip_word(obj, ptr, end, is_address_64bit);
    case DW_FORM_block1: {
      uint8_t len;
      return read_uint8_t(obj, ptr, end, &len) && skip_bytes(obj, ptr, end, len);
    }
    case DW_FORM_block2: {
      uint16_t len;
      return read_uint16_t(obj, ptr, end, &len) && skip_bytes(obj, ptr, end, len);
    }    
    case DW_FORM_block4: {
      uint32_t len;
      return read_uint32_t(obj, ptr, end, &len) && skip_bytes(obj, ptr, end, len);
    }
    case DW_FORM_block: {
      uint64_t len;
      return read_uLEB128(obj, ptr, end, &len) && skip_bytes(obj, ptr, end, len);
    }
    case DW_FORM_flag:
    case DW_FORM_ref1:
    case DW_FORM_data1:
      return skip_uint8_t(obj, ptr, end);
    case DW_FORM_ref2:
    case DW_FORM_data2:
      return skip_uint16_t(obj, ptr, end);
    case DW_FORM_ref4:
    case DW_FORM_data4:
      return skip_uint32_t(obj, ptr, end);
    case DW_FORM_ref8:
    case DW_FORM_data8:
      return skip_uint64_t(obj, ptr, end);
    case DW_FORM_string:
      return skip_ASCIIZ(obj, ptr, end);
    case DW_FORM_ref_udata:
    case DW_FORM_sdata:
    case DW_FORM_udata:
      return skip_LEB128(obj, ptr, end);
    case DW_FORM_strp:
      return skip_word(obj, ptr, end, is_info_64bit);
    case DW_FORM_indirect:
      dwarf2_invalid_warning(obj, "Double indirect form!");
      return 0;
    default:
      dwarf2_invalid_warning(obj, "Unknown form %d", form);
      return 0;
  }
}

static int find_attribute(EntryReader* reader, CH_Dwarf2_DW_AT attribute,
    uint8_t** data, CH_Dwarf2_DW_FORM* form) {
  uint8_t* attr = reader->abbrev_ptr;
  uint8_t* entry_ptr = reader->entry_ptr;
  CH_DbgDwarf2Object* obj = reader->cu_reader->obj;
  
  *form = 0;
  for (;;) {
    uint64_t name;
    uint64_t attr_form;
    if (!read_uLEB128(obj, &attr, reader->abbrev_end, &name))
      return 0;
    if (!name)
      return 1; /* no more attributes */
    if (!read_uLEB128(obj, &attr, reader->abbrev_end, &attr_form))
      return 0;
    if (attr_form == DW_FORM_indirect) {
      /* indirect form, so read the actual form from the entry */
      if (!read_uLEB128(obj, &entry_ptr, reader->entry_end, &attr_form))
        return 0;
    }
    if (name == attribute) {
      *form = attr_form;
      *data = entry_ptr;
      return 1;
    }
    if (!skip_form(obj, &entry_ptr, reader->entry_end, attr_form,
                   reader->cu_reader->is_address_64bit,
                   reader->cu_reader->is_info_64bit))
      return 0;
  }
}

static int convert_64bit_offset(CH_DbgDwarf2Object* obj, uint64_t w,
                                CH_DbgDwarf2Offset* offset) {
  if ((CH_DbgDwarf2Offset)w != w) {
    dwarf2_invalid_warning(obj, "Encountered 64-bit reference on a 32-bit platform");
    return 0;
  }
  *offset = w;
  return 1;
}

static int read_attribute_unsigned_constant(EntryReader* reader,
    CH_Dwarf2_DW_AT attribute, uint64_t* v, int* found) {
  uint8_t* data;
  CH_Dwarf2_DW_FORM form;
  CH_DbgDwarf2Object* obj = reader->cu_reader->obj;

  if (!find_attribute(reader, attribute, &data, &form))
    return 0;
  *found = form != 0;

  switch (form) {
    case 0: /* attribute not found */
      return 1;
    case DW_FORM_udata:
      return read_uLEB128(obj, &data, reader->entry_end, v);
    case DW_FORM_sdata: {
      int64_t sv;
      if (!read_LEB128(obj, &data, reader->entry_end, &sv))
        return 0;
      if (sv < 0) {
        dwarf2_invalid_warning(obj, "Negative signed constant used in unsigned context");
        return 0;
      }
      *v = sv;
      return 1;
    }
    case DW_FORM_data8:
      return read_uint64_t(obj, &data, reader->entry_end, v);
    case DW_FORM_data4: {
      uint32_t w;
      if (!read_uint32_t(obj, &data, reader->entry_end, &w))
        return 0;
      *v = w;
      return 1;
    }
    case DW_FORM_data2: {
      uint16_t w;
      if (!read_uint16_t(obj, &data, reader->entry_end, &w))
        return 0;
      *v = w;
      return 1;
    }
    case DW_FORM_data1: {
      uint8_t w;
      if (!read_uint8_t(obj, &data, reader->entry_end, &w))
        return 0;
      *v = w;
      return 1;
    }
    default:
      dwarf2_invalid_warning(obj, "Reference form %d not supported", form);
      return 0;
  }
}

static int read_attribute_signed_constant(EntryReader* reader,
    CH_Dwarf2_DW_AT attribute, int64_t* v, int* found) {
  uint8_t* data;
  CH_Dwarf2_DW_FORM form;
  CH_DbgDwarf2Object* obj = reader->cu_reader->obj;

  if (!find_attribute(reader, attribute, &data, &form))
    return 0;
  *found = form != 0;

  switch (form) {
    case 0: /* attribute not found */
      return 1;
    case DW_FORM_sdata:
      return read_LEB128(obj, &data, reader->entry_end, v);
    case DW_FORM_udata: {
      uint64_t sv;
      if (!read_uLEB128(obj, &data, reader->entry_end, &sv))
        return 0;
      if ((int64_t)sv != sv) {
        dwarf2_invalid_warning(obj, "Oversized signed constant used in signed context");
        return 0;
      }
      *v = sv;
      return 1;
    }
    case DW_FORM_data8: {
      uint64_t w;
      if (!read_uint64_t(obj, &data, reader->entry_end, &w))
        return 0;
      *v = (int64_t)w;
      return 1;
    }
    case DW_FORM_data4: {
      uint32_t w;
      if (!read_uint32_t(obj, &data, reader->entry_end, &w))
        return 0;
      *v = (int32_t)w;
      return 1;
    }
    case DW_FORM_data2: {
      uint16_t w;
      if (!read_uint16_t(obj, &data, reader->entry_end, &w))
        return 0;
      *v = (int16_t)w;
      return 1;
    }
    case DW_FORM_data1: {
      uint8_t w;
      if (!read_uint8_t(obj, &data, reader->entry_end, &w))
        return 0;
      *v = (int8_t)w;
      return 1;
    }
    default:
      dwarf2_invalid_warning(obj, "Reference form %d not supported", form);
      return 0;
  }
}

static int read_attribute_address(EntryReader* reader,
    CH_Dwarf2_DW_AT attribute, uint64_t* addr, int* found) {
  uint8_t* data;
  CH_Dwarf2_DW_FORM form;
  CH_DbgDwarf2Object* obj = reader->cu_reader->obj;

  if (!find_attribute(reader, attribute, &data, &form))
    return 0;
  *found = form != 0;
  if (!*found)
    return 1;

  if (form != DW_FORM_addr) {
    dwarf2_invalid_warning(obj, "Address not DW_FORM_addr");
    return 0;
  }
  return read_uword(obj, &data, reader->entry_end, addr,
                    reader->cu_reader->is_address_64bit);
}

static int read_attribute_flag(EntryReader* reader,
    CH_Dwarf2_DW_AT attribute, int* found) {
  uint8_t* data;
  CH_Dwarf2_DW_FORM form;
  CH_DbgDwarf2Object* obj = reader->cu_reader->obj;

  if (!find_attribute(reader, attribute, &data, &form))
    return 0;
  if (form == 0) {
    *found = 0;
    return 1;
  }

  if (form != DW_FORM_flag) {
    dwarf2_invalid_warning(obj, "Flag not DW_FORM_flag");
    return 0;
  }
  *found = data[0] != 0;
  return 1;
}

static uint8_t* get_block(CH_DbgDwarf2Object* obj,
                          uint8_t* data, uint8_t* end,
                          CH_Dwarf2_DW_FORM form, uintptr_t* size) {
  switch (form) {
    case DW_FORM_block1: {
      uint8_t len;
      if (!read_uint8_t(obj, &data, end, &len))
        return NULL;
      *size = len;
      break;
    }
    case DW_FORM_block2: {
      uint16_t len;
      if (!read_uint16_t(obj, &data, end, &len))
        return NULL;
      *size = len;
      break;
    }
    case DW_FORM_block4: {
      uint32_t len;
      if (!read_uint32_t(obj, &data, end, &len))
        return NULL;
      *size = len;
      break;
    }
    case DW_FORM_block: {
      uint64_t len;
      if (!read_uLEB128(obj, &data, end, &len))
        return NULL;
      *size = len;
      break;
    }
    default:
      dwarf2_invalid_warning(obj, "Unknown block form %d", form);
      return NULL;
  }
  return data;
}

static int read_attribute_listptr(EntryReader* reader,
    CH_Dwarf2_DW_AT attribute, CH_DbgDwarf2Offset* addr, int* found) {
  uint8_t* data;
  CH_Dwarf2_DW_FORM form;
  uint64_t offset;
  CH_DbgDwarf2Object* obj = reader->cu_reader->obj;
  
  if (!find_attribute(reader, attribute, &data, &form))
    return 0;
  *found = form != 0;
  if (!*found)
    return 1;

  if (form != DW_FORM_data4 && form != DW_FORM_data8) {
    dwarf2_invalid_warning(obj, "listptr not DW_FORM_data4 or DW_FORM_data8");
    return 0;
  }
  if (!read_uword(obj, &data, reader->entry_end, &offset, form == DW_FORM_data8))
    return 0;
  return convert_64bit_offset(obj, offset, addr);
}

static int read_attribute_reference(EntryReader* reader,
    CH_Dwarf2_DW_AT attribute, CH_DbgDwarf2Offset* ref, int* found) {
  uint8_t* data;
  CH_Dwarf2_DW_FORM form;
  CH_DbgDwarf2Object* obj = reader->cu_reader->obj;
  CH_DbgDwarf2Offset cu_base = reader->cu_reader->cu_offset;
  
  if (!find_attribute(reader, attribute, &data, &form))
    return 0;
  *found = form != 0;

  switch (form) {
    case 0: /* attribute not found */
      return 1;
    case DW_FORM_ref8: {
      uint64_t w;
      if (!read_uint64_t(obj, &data, reader->entry_end, &w))
        return 0;
      return convert_64bit_offset(obj, w + cu_base, ref);
    }
    case DW_FORM_ref4: {
      uint32_t w;
      if (!read_uint32_t(obj, &data, reader->entry_end, &w))
        return 0;
      *ref = w + cu_base;
      return 1;
    }
    case DW_FORM_ref2: {
      uint16_t w;
      if (!read_uint16_t(obj, &data, reader->entry_end, &w))
        return 0;
      *ref = w + cu_base;
      return 1;
    }
    case DW_FORM_ref1: {
      uint8_t w;
      if (!read_uint8_t(obj, &data, reader->entry_end, &w))
        return 0;
      *ref = w + cu_base;
      return 1;
    }
    case DW_FORM_ref_udata: {
      uint64_t w;
      if (!read_uLEB128(obj, &data, reader->entry_end, &w))
        return 0;
      return convert_64bit_offset(obj, w + cu_base, ref);
    }
    case DW_FORM_ref_addr:
      dwarf2_invalid_warning(obj, "DW_FORM_ref_addr not supported");
      return 0;
    default:
      dwarf2_invalid_warning(obj, "Reference form %d not supported", form);
      return 0;
  }
}

static int check_ASCIIZ(uint64_t offset, Elf_Data* section) {
  if (!section)
    return 0;
  for (;;) {
    if (offset >= section->d_size)
      return 0;
    if (((const char*)section->d_buf)[offset] == 0)
      return 1;
    ++offset;
  }
}

static int read_attribute_string(EntryReader* reader,
    CH_Dwarf2_DW_AT attribute, const char** str, int* found) {
  uint8_t* data;
  CH_DbgDwarf2Object* obj = reader->cu_reader->obj;
  CH_Dwarf2_DW_FORM form;
  if (!find_attribute(reader, attribute, &data, &form))
    return 0;
  *found = form != 0;
  switch (form) {
    case 0: /* attribute not found */
      return 1;
    case DW_FORM_string:
      *found = 1;
      *str = data[0] ? (const char*)data : NULL;
      return 1;
    case DW_FORM_strp: {
      uint64_t ref;
      if (!read_uword(obj, &data, reader->entry_end, &ref,
                      reader->cu_reader->is_info_64bit))
        return 0;
      if (!check_ASCIIZ(ref, obj->debug_str_data))
        return 0;
      *found = 1;
      *str = ((const char*)obj->debug_str_data->d_buf) + ref;
      if (!(*str)[0]) {
        *str = NULL;
      }
      return 1;
    }
    default:
      dwarf2_invalid_warning(obj, "String form %d not supported", form);
      return 0;
  }
}      

/**
 * Find the end of this entry --- which is the start of the next entry,
 * in the flattened tree preorder.
 */
static CH_DbgDwarf2Offset find_end_of_entry(EntryReader* reader) {
  uint8_t* attr = reader->abbrev_ptr;
  uint8_t* entry_ptr = reader->entry_ptr;
  CH_DbgDwarf2Object* obj = reader->cu_reader->obj;
  uint8_t* base = get_debuginfo_base(obj);
  
  if (reader->is_empty)
    return entry_ptr - base;
  
  for (;;) {
    uint64_t name;
    uint64_t attr_form;
    if (!read_uLEB128(obj, &attr, reader->abbrev_end, &name))
      return 0;
    if (!name)
      return entry_ptr - base;
    if (!read_uLEB128(obj, &attr, reader->abbrev_end, &attr_form))
      return 0;
    if (attr_form == DW_FORM_indirect) {
      /* indirect form, so read the actual form from the entry */
      if (!read_uLEB128(obj, &entry_ptr, reader->entry_end, &attr_form))
        return 0;
    }
    if (!skip_form(obj, &entry_ptr, reader->entry_end, attr_form,
                   reader->cu_reader->is_address_64bit,
                   reader->cu_reader->is_info_64bit))
      return 0;
  }
}

/**
 * Find the end of this entry's subtree --- which is the start of the entry's
 * next sibling.
 */
static CH_DbgDwarf2Offset find_end_of_entry_subtree(EntryReader* reader) {
  uint8_t* entry_ptr = reader->entry_ptr;
  uint8_t* base = get_debuginfo_base(reader->cu_reader->obj);
  CH_DbgDwarf2Offset ref;
  CH_DbgDwarf2Offset child_offset;
  int found;
  
  if (reader->is_empty)
    return entry_ptr - base;
  
  if (!reader->has_children)
    return find_end_of_entry(reader);

  if (!read_attribute_reference(reader, DW_AT_sibling, &ref, &found))
    return 0;
  if (found)
    return ref;

  /* ugh. We need to manually scan the children. */
  child_offset = find_end_of_entry(reader);
  for (;;) {
    EntryReader child_reader;
    
    if (!child_offset)
      return 0;
    if (!begin_reading_entry(reader->cu_reader, child_offset, &child_reader))
      return 0;
    if (child_reader.is_empty) {
      /* this is the last child, we're done! */
      return child_reader.entry_ptr - base;
    }
    
    child_offset = find_end_of_entry_subtree(&child_reader);
  }
}

static CH_DbgDwarf2Offset find_compilation_unit_offset_for(
    CH_DbgDwarf2Object* obj, CH_DbgDwarf2Offset defining_object_offset) {
  uint32_t start = 0;
  uint32_t end = obj->num_compilation_units;
  while (start + 2 <= end) {
    uint32_t mid = (start + end)/2;
    if (obj->debuginfo_compilation_unit_offsets[mid] > defining_object_offset) {
      end = mid;
    } else {
      start = mid;
    }
  }
  if (start == end)
    return 0;
  return obj->debuginfo_compilation_unit_offsets[start];
}

/**
 * @return 1 to continue iterating
 */
typedef int (* EntryAncestorVisitorCallback)(void* closure,
    CH_DbgDwarf2Offset entry_offset, EntryReader* reader);

static int visit_entry_ancestor_chain(CompilationUnitReader* cu_reader,
    CH_DbgDwarf2Offset target_offset, EntryAncestorVisitorCallback callback,
    void* callback_closure) {
  CH_DbgDwarf2Offset entry_offset;

  entry_offset = cu_reader->first_entry;
    
  for (;;) {
    int status;
    CH_DbgDwarf2Offset child_offset;
    EntryReader reader;
    
    if (!begin_reading_entry(cu_reader, entry_offset, &reader))
      return 0;

    status = callback(callback_closure, entry_offset, &reader);
    if (status != 1)
      return status;
    
    if (entry_offset == target_offset)
      return 1;

    /* now ... which of our children, if any, contains the target? */
    if (reader.is_empty || !reader.has_children) {
      /* we failed to find the target! */
      return 0;
    }

    child_offset = find_end_of_entry(&reader);
    if (!child_offset)
      return 0;
    for (;;) {
      EntryReader child_reader;
      CH_DbgDwarf2Offset next_child_offset;
      
      if (!begin_reading_entry(cu_reader, child_offset, &child_reader))
        return 0;
      if (child_reader.is_empty) {
        /* we failed to find the target! */
        return 0;
      }
      
      next_child_offset = find_end_of_entry_subtree(&child_reader);
      if (!next_child_offset)
        return 0;
      if (child_offset <= target_offset && target_offset < next_child_offset) {
        /* The target is in this child's subtree */
        entry_offset = child_offset;
        break;
      }
      
      child_offset = next_child_offset;
    }
  }
}

static const char* get_anon_name(CH_Dwarf2_DW_TAG tag) {
  switch (tag) {
    case DW_TAG_namespace: return "(anon-namespace)";
    case DW_TAG_base_type: return "(anon-basetype)";
    case DW_TAG_class_type: return "(anon-class)";
    case DW_TAG_interface_type: return "(anon-interface)";
    case DW_TAG_structure_type: return "(anon-struct)";
    case DW_TAG_union_type:  return "(anon-union)";
    default: return NULL;
  }
}

static int begin_reading_first_entry(CompilationUnitReader* cu_reader,
    EntryReader* reader) {
  if (!begin_reading_entry(cu_reader, cu_reader->first_entry, reader))
    return 0;
  if (reader->tag != DW_TAG_compile_unit) {
    dwarf2_invalid_warning(cu_reader->obj,
                           "Expected first entry to be compilation unit, but has tag %d",
                           reader->tag);
    return 0;
  }
  return 1;
}

static CH_Dwarf2_DW_LANG get_language(CompilationUnitReader* cu_reader) {
  EntryReader reader;
  int found;
  uint64_t language;

  if (!begin_reading_first_entry(cu_reader, &reader))
    return 0;
  
  if (!read_attribute_unsigned_constant(&reader, DW_AT_language, &language, &found))
    return 0;
  if (!found) {
    dwarf2_invalid_warning(cu_reader->obj, "Compilation_unit should have a language");
    return 0;
  }
  if (language > DW_LANG_MAX) {
    dwarf2_invalid_warning(cu_reader->obj, "Invalid language %d", language);
    return 0;
  }
  
  return language;
}

static const char* get_language_string(CH_DbgDwarf2Object* obj,
                                       CH_Dwarf2_DW_LANG language) {
  switch (language) {
    case DW_LANG_C89: return "C89";
    case DW_LANG_C: return "C";
    case DW_LANG_Ada83: return "Ada83";
    case DW_LANG_C_plus_plus: return "C++";
    case DW_LANG_Cobol74: return "Cobol74";
    case DW_LANG_Cobol85: return "Cobol85";
    case DW_LANG_Fortran77: return "Fortran77";
    case DW_LANG_Fortran90: return "Fortran90";
    case DW_LANG_Pascal83: return "Pascal83";
    case DW_LANG_Modula2: return "Modula2";
    case DW_LANG_Java: return "Java";
    case DW_LANG_C99: return "C99";
    case DW_LANG_Ada95: return "Ada95";
    case DW_LANG_Fortran95: return "Fortran95";
    case DW_LANG_PLI: return "PLI";
    case DW_LANG_MIPSasm: return "Assembly";
    default:
      dwarf2_invalid_warning(obj, "Unknown language %d", language);
      return NULL;
  }
}

static const char* get_namespace_separator(CH_DbgDwarf2Object* obj,
                                           CH_Dwarf2_DW_LANG language) {
  switch (language) {
    case DW_LANG_C89:
    case DW_LANG_C:
    case DW_LANG_C99:
    case DW_LANG_MIPSasm:
    case DW_LANG_Fortran77:
    case DW_LANG_Fortran90:
    case DW_LANG_Fortran95:
    case DW_LANG_Cobol74:
    case DW_LANG_Cobol85:
    case 0:
      return NULL;
    case DW_LANG_C_plus_plus:
      return "::";
    case DW_LANG_Java:
      return ".";
    default:
      dwarf2_invalid_warning(obj, "Unsupported language %d", language);
      return NULL;
  }
}

static const char* get_container_separator(CH_DbgDwarf2Object* obj,
                                           CH_Dwarf2_DW_LANG language) {
  return get_namespace_separator(obj, language);
}

typedef struct {
  CompilationUnitReader* cu_reader;
  CH_StringBuf* namespace_prefix;
  CH_StringBuf* container_prefix;
  CH_DbgDwarf2Offset info_offset;
  CH_Dwarf2_DW_LANG language;
} ExtractPrefixesClosure;

static int extract_prefixes(CompilationUnitReader* cu_reader,
    CH_StringBuf* namespace_prefix, CH_StringBuf* container_prefix,
    CH_DbgDwarf2Offset info_offset);
    
static int extract_prefixes_callback(void* closure,
    CH_DbgDwarf2Offset entry_offset, EntryReader* reader) {
  ExtractPrefixesClosure* cl = closure;
  CH_DbgDwarf2Offset ref;
  int found;

  if (!read_attribute_reference(reader, DW_AT_specification, &ref, &found))
    return 0;
  if (!found) {
    if (!read_attribute_reference(reader, DW_AT_extension, &ref, &found))
      return 0;
  }
  if (found) {
    /* The container and namespace data up to this type/namespace/whatever
       should be obtained from its initial declaration */
    stringbuf_set(cl->namespace_prefix, "");
    stringbuf_set(cl->container_prefix, "");
    
    if (entry_offset == cl->info_offset) {
      /* remember not to include the particulars of the target object */
      cl->info_offset = ref;
      return visit_entry_ancestor_chain(cl->cu_reader, ref,
                                        extract_prefixes_callback, cl);
    }

    if (!visit_entry_ancestor_chain(cl->cu_reader, ref,
                                    extract_prefixes_callback, cl))
      return 0;
  } else {
    if (entry_offset == cl->info_offset)
      return 1;
    
    switch (reader->tag) {
      case DW_TAG_namespace: {
        const char* name;
        const char* separator =
          get_namespace_separator(cl->cu_reader->obj, cl->language);
        if (!separator)
          return 0;

        if (!read_attribute_string(reader, DW_AT_name, &name, &found))
          return 0;
        stringbuf_append(cl->namespace_prefix, found ? name :
                         get_anon_name(reader->tag));
        stringbuf_append(cl->namespace_prefix, separator);
      }
      case DW_TAG_base_type:
      case DW_TAG_class_type:
      case DW_TAG_interface_type:
      case DW_TAG_structure_type:
      case DW_TAG_union_type: {
        const char* name;
        const char* separator =
          get_container_separator(cl->cu_reader->obj, cl->language);
        if (!separator)
          return 0;
          
        if (!read_attribute_string(reader, DW_AT_name, &name, &found))
          return 0;
        stringbuf_append(cl->container_prefix, found ? name :
                         get_anon_name(reader->tag));
        stringbuf_append(cl->container_prefix, separator);
      }
      default:
        break;
    }
  }
  
  return 1;
}

static int extract_prefixes(CompilationUnitReader* cu_reader,
    CH_StringBuf* namespace_prefix, CH_StringBuf* container_prefix,
    CH_DbgDwarf2Offset info_offset) {
  ExtractPrefixesClosure cl =
    { cu_reader, namespace_prefix, container_prefix, info_offset,
      get_language(cu_reader) };
  if (!cl.language)
    return 0;

  return visit_entry_ancestor_chain(cu_reader, info_offset,
                                    extract_prefixes_callback, &cl);
}

static int lookup_compilation_unit_info(CompilationUnitReader* cu_reader,
    CH_DbgDwarf2CompilationUnitInfo* cu_info) {
  CH_Dwarf2_DW_LANG language = get_language(cu_reader);
  EntryReader reader;
  const char* name;
  const char* comp_dir;
  int found;

  if (!language)
    return 0;
  cu_info->language = get_language_string(cu_reader->obj, language);

  if (!begin_reading_first_entry(cu_reader, &reader))
    return 0;
  
  if (!read_attribute_string(&reader, DW_AT_name, &name, &found))
    return 0;
  cu_info->compilation_unit = found ? name : NULL;

  if (!read_attribute_string(&reader, DW_AT_comp_dir, &comp_dir, &found))
    return 0;
  cu_info->compilation_unit_dir = found ? comp_dir : NULL;
  return 1;
}

/**** LINE NUMBER PARSING *****/

typedef struct {
  uint64_t    address; /* dwarf address */
  const char* file_name;
  uint32_t    line_number;
} LineNumberEntry;
typedef struct {
  /* sorted by address non-decreasing order */
  LineNumberEntry* line_number_entries;
  uint32_t         line_number_entry_count;
} LineNumberTable;

static void free_line_number_table(LineNumberTable* table) {
  safe_free(table->line_number_entries);
}

static void append_buf(CH_GrowBuf* buf, uint32_t* size, void* data, uint32_t len) {
  ensure_buffer_size(buf, *size + len);
  memcpy(buf->data + *size, data, len);
  *size += len;
}

static const char* resolve_file_name(const char* d1, const char* d2, const char* f) {
  CH_StringBuf buf;

  if (f[0] == '/')
    return f;
 
  stringbuf_init(&buf);
  if (d2[0] != '/') {
    stringbuf_append(&buf, d1);
    stringbuf_append(&buf, "/");
  }
  stringbuf_append(&buf, d2);
  stringbuf_append(&buf, "/");
  stringbuf_append(&buf, f);
  
  canonicalize_pathname(&buf);
  
  return stringbuf_finish(&buf);
}

static int append_file_record(CompilationUnitReader* cu_reader,
    CH_GrowBuf* file_name_ptr_buf,
    uint8_t** ptr, uint8_t* ptr_end, uint32_t dir_count, void* dir_name_array,
    const char* compilation_dir_name, const char* file_name) {
  uint64_t directory_index;
  const char* directory_name;
  CH_DbgDwarf2Object* obj = cu_reader->obj;
  const char* resolved_name;
  
  if (!skip_ASCIIZ(obj, ptr, ptr_end) ||
      !read_uLEB128(obj, ptr, ptr_end, &directory_index) ||
      !skip_LEB128(obj, ptr, ptr_end) ||
      !skip_LEB128(obj, ptr, ptr_end))
    return 0;
  if (directory_index > dir_count) {
    dwarf2_invalid_warning(obj, "Bad directory index %d", directory_index);
    return 0;
  }
  if (directory_index == 0) {
    directory_name = ".";
  } else {
    directory_name = ((const char**)dir_name_array)[directory_index - 1];
  }
  
  resolved_name = resolve_file_name(compilation_dir_name, directory_name, file_name);
  ensure_buffer_size(file_name_ptr_buf,
                     sizeof(char*)*(cu_reader->abbrev_offsets->file_count + 1));
  cu_reader->abbrev_offsets->file_names = (const char**)file_name_ptr_buf->data;
  cu_reader->abbrev_offsets->file_names[cu_reader->abbrev_offsets->file_count] = resolved_name;
  cu_reader->abbrev_offsets->file_count++;
  return 1;
}

static int append_line_number_entry(CompilationUnitReader* cu_reader,
    CH_GrowBuf* line_buf, uint32_t* line_buf_count,
    uint64_t address, uint64_t file, uint64_t line) {
  LineNumberEntry* entry;
  CH_DbgDwarf2Object* obj = cu_reader->obj;
  
  if (file > cu_reader->abbrev_offsets->file_count || file == 0) {
    dwarf2_invalid_warning(obj, "Invalid file index %d", file);
    return 0;
  }
  if ((uint32_t)line != line) {
    dwarf2_invalid_warning(obj, "Line number overflow");
    return 0;
  }
  
  ensure_buffer_size(line_buf, (*line_buf_count + 1)*sizeof(LineNumberEntry));
  entry = (LineNumberEntry*)line_buf->data + *line_buf_count;
  entry->address = address;
  entry->file_name = cu_reader->abbrev_offsets->file_names[file - 1];
  entry->line_number = (uint32_t)line;
  (*line_buf_count)++;
  return 1;
}

static void adjust_for_special_op(uint8_t special, int8_t line_base,
    uint8_t line_range, uint8_t min_instruction_length,
    uint64_t* address, uint64_t* line) {
  if (address) {
    *address += (special/line_range)*min_instruction_length;
  }
  if (line) {
    *line += line_base + special%line_range;
  }
}

/*
 * Read the line number data for a compilation unit and fill in 'table'. If
 * 'table' is NULL then we just collect all the files and fill in the file
 * data for the compilation unit's AbbrevOffsets.
 */
static int get_line_number_table(QueryThread* q, CompilationUnitReader* cu_reader,
    LineNumberTable* table) {
  CH_GrowBuf line_buf;
  CH_GrowBuf dir_ptr_buf;
  CH_GrowBuf file_name_buf;
  uint32_t line_buf_count = 0;
  uint32_t dir_ptr_buf_size = 0;
  uint64_t lineptr;
  int found;
  EntryReader cu_entry_reader;
  CH_DbgDwarf2Object* obj = cu_reader->obj;
  Elf_Data* elf_data = obj->debug_line_data;
  uint8_t* ptr;
  uint8_t* ptr_end;
  CH_DbgDwarf2Offset length;
  uint16_t version;
  uint64_t header_length;
  int is_64bit;
  uint8_t min_instruction_length;
  int8_t line_base;
  uint8_t line_range;
  uint8_t opcode_base;
  uint8_t* standard_opcode_lengths;
  uint32_t dir_count = 0;
  uint8_t* program;
  uint64_t reg_address = 0;
  uint64_t reg_file = 1;
  uint64_t reg_line = 1;
  int OK = 1;
  const char* compilation_unit_dir = ".";
  
  if (table) {
    dbg_wait_for_global_symbols(q);
    table->line_number_entries = NULL;
    table->line_number_entry_count = 0;
  }

  if (!begin_reading_first_entry(cu_reader, &cu_entry_reader) ||
      cu_entry_reader.is_empty ||
      !read_attribute_unsigned_constant(&cu_entry_reader, DW_AT_stmt_list, &lineptr, &found))
    return 0;
  if (!found)
    return 1;
  
  if (!read_attribute_string(&cu_entry_reader, DW_AT_comp_dir, &compilation_unit_dir, &found))
    return 0;
  
  if (!elf_data) {
    dwarf2_invalid_warning(obj, "No .debug_line section found");
    return 0;
  }

  ptr = elf_data->d_buf + lineptr;
  ptr_end = ptr + elf_data->d_size;

  if (!read_initial_length(obj, &ptr, ptr_end, &length, &is_64bit))
    return 0;
  if (ptr + length > ptr_end) {
    dwarf2_invalid_warning(obj, "Overlong line data");
    return 0;
  }
  ptr_end = ptr + length;
  if (!read_uint16_t(obj, &ptr, ptr_end, &version))
    return 0;
  if (version != 2 && version != 3) {
    dwarf2_invalid_warning(obj, "Unknown line table version %d", version);
    return 0;
  }
  if (!read_uword(obj, &ptr, ptr_end, &header_length, is_64bit))
    return 0;
  program = ptr + header_length;
  if (program > ptr_end) {
    dwarf2_invalid_warning(obj, "Overlong header data");
    return 0;
  }
  if (!read_uint8_t(obj, &ptr, ptr_end, &min_instruction_length) ||
      !skip_uint8_t(obj, &ptr, ptr_end) ||
      !read_int8_t(obj, &ptr, ptr_end, &line_base) ||
      !read_uint8_t(obj, &ptr, ptr_end, &line_range) ||
      !read_uint8_t(obj, &ptr, ptr_end, &opcode_base))
    return 0;
  if (opcode_base < 1) {
    dwarf2_invalid_warning(obj, "Bad opcode_base %d", opcode_base);
    return 0;
  }
  standard_opcode_lengths = ptr;
  if (!skip_bytes(obj, &ptr, ptr_end, opcode_base - 1))
    return 0;
  init_buf(&dir_ptr_buf);
  /* read directory list */
  for (;;) {
    char* dir_name = (char*)ptr;
    uint8_t first_char;
    if (!read_uint8_t(obj, &ptr, ptr_end, &first_char)) {
      safe_free(dir_ptr_buf.data);
      return 0;
    }
    if (!first_char)
      break;
    if (!skip_ASCIIZ(obj, &ptr, ptr_end)) {
      safe_free(dir_ptr_buf.data);
      return 0;
    }
    if (!table) {
      append_buf(&dir_ptr_buf, &dir_ptr_buf_size, &dir_name, sizeof(dir_name));
      ++dir_count;
    }
  }
  /* read file list */
  init_buf(&file_name_buf);
  for (;;) {
    char* file_name = (char*)ptr;
    uint8_t first_char;
    if (!read_uint8_t(obj, &ptr, ptr_end, &first_char)) {
      safe_free(dir_ptr_buf.data);
      safe_free(file_name_buf.data);
      if (!table) {
        cu_reader->abbrev_offsets->file_count = 0;
        cu_reader->abbrev_offsets->file_names = NULL;
      }
      return 0;
    }
    if (!first_char)
      break;
    if (!table) {
      if (!append_file_record(cu_reader, &file_name_buf, &ptr, ptr_end, dir_count,
                              dir_ptr_buf.data, compilation_unit_dir, file_name)) {
        safe_free(dir_ptr_buf.data);
        safe_free(file_name_buf.data);
        cu_reader->abbrev_offsets->file_count = 0;
        cu_reader->abbrev_offsets->file_names = NULL;
        return 0;
      }
    }
  }
  
  init_buf(&line_buf);
  
  ptr = program;
  while (OK && ptr < ptr_end) {
    uint8_t opcode = *ptr;
    ptr++;
    if (opcode < opcode_base) {
      switch (opcode) {
        case 0: {
          uint64_t len;
          uint8_t* op_end;
          uint8_t extended_opcode;
          if (!read_uLEB128(obj, &ptr, ptr_end, &len)) {
            OK = 0;
            break;
          }
          op_end = ptr + len;
          if (!read_uint8_t(obj, &ptr, op_end, &extended_opcode)) {
            OK = 0;
            break;
          }
          switch (extended_opcode) {
            case DW_LNE_end_sequence:
              if (table) {
                if (!append_line_number_entry(cu_reader, &line_buf, &line_buf_count,
                        reg_address, reg_file, reg_line)) {
                  OK = 0;
                }
              }
              reg_address = 0;
              reg_file = 1;
              reg_line = 1;
              break;
            
            case DW_LNE_define_file:
              if (!table) {
                if (!append_file_record(cu_reader, &file_name_buf, &ptr, ptr_end, dir_count,
                                        dir_ptr_buf.data, compilation_unit_dir, (char*)ptr)) {
                  OK = 0;
                  break;
                }
              }
              break;
              
            case DW_LNE_set_address: {
              uint64_t addr;
              /* XXX we may need to apply ELF relocations here */
              if (!read_uword(obj, &ptr, ptr_end, &addr, cu_reader->is_address_64bit)) {
                OK = 0;
                break;
              }
              reg_address = addr;
              break;
            }

            default:
              dwarf2_invalid_warning(obj, "Unknown extended opcode %d", extended_opcode);
              break;
          }
          ptr = op_end;
          break;
        }
        case DW_LNS_copy:
          if (table) {
            if (!append_line_number_entry(cu_reader, &line_buf, &line_buf_count,
                    reg_address, reg_file, reg_line)) {
              OK = 0;
            }
          }
          break;
        case DW_LNS_advance_pc: {
          uint64_t delta;
          if (!read_uLEB128(obj, &ptr, ptr_end, &delta)) {
            OK = 0;
            break;
          }
          reg_address += delta*min_instruction_length;
          break;
        }
        case DW_LNS_advance_line: {
          uint64_t delta;
          if (!read_uLEB128(obj, &ptr, ptr_end, &delta)) {
            OK = 0;
            break;
          }
          reg_line += delta*min_instruction_length;
          break;
        }
        case DW_LNS_set_file: {
          uint64_t f;
          if (!read_uLEB128(obj, &ptr, ptr_end, &f)) {
            OK = 0;
            break;
          }
          reg_file = f;
          break;
        }
        case DW_LNS_const_add_pc:
          adjust_for_special_op(255 - opcode_base, line_base, line_range,
              min_instruction_length, &reg_address, NULL);
          break;
        case DW_LNS_fixed_advance_pc: {
          uint16_t delta;
          if (!read_uint16_t(obj, &ptr, ptr_end, &delta)) {
            OK = 0;
            break;
          }
          reg_address += delta;
          break;
        }
        default: {
          int i;
          for (i = 0; i < standard_opcode_lengths[opcode]; ++i) {
            if (!skip_LEB128(obj, &ptr, ptr_end)) {
              OK = 0;
              break;
            }
          }
          break;
        }
      }
    } else {
      adjust_for_special_op(opcode - opcode_base, line_base, line_range,
          min_instruction_length, &reg_address, &reg_line);
      if (table) {
        if (!append_line_number_entry(cu_reader, &line_buf, &line_buf_count,
                reg_address, reg_file, reg_line)) {
          OK = 0;
        }
      }
    }
  }

  safe_free(dir_ptr_buf.data);
  if (!OK) {
    safe_free(line_buf.data);
    safe_free(file_name_buf.data);
    if (!table) {
      cu_reader->abbrev_offsets->file_count = 0;
      cu_reader->abbrev_offsets->file_names = NULL;
    }
    return 0;
  }
  if (table) {
    table->line_number_entries =
      safe_realloc(line_buf.data, sizeof(LineNumberEntry)*line_buf_count);
    table->line_number_entry_count = line_buf_count;
  } else {
    cu_reader->abbrev_offsets->file_names =
      safe_realloc(file_name_buf.data, sizeof(const char*)*cu_reader->abbrev_offsets->file_count);
  }
  return 1;
}

/* find last line number entry with address <= addr; return NULL if none */
static LineNumberEntry* find_line_number_entry_for(LineNumberTable* table,
    uint64_t addr) {
  uint32_t start = 0;
  uint32_t end = table->line_number_entry_count;
  while (end - start > 1) {
    uint32_t mid = (start + end)/2;
    if (table->line_number_entries[mid].address <= addr) {
      start = mid;
    } else {
      end = mid;
    }
  }
  if (start >= end)
    return NULL;
  if (table->line_number_entries[start].address > addr)
    return NULL;
  return &table->line_number_entries[start];
}

/***** ADDRESS RANGES *****/

static int compare_by_start(const void* v1, const void* v2) {
  const ARangeEntry* e1 = v1;
  const ARangeEntry* e2 = v2;
  if (e1->start < e2->start)
    return -1;
  if (e1->start > e2->start)
    return 1;
  return 0;
}

static ARangeEntry* sort_and_remove_overlaps(CH_DbgDwarf2Object* obj,
                                             ARangeEntry* entries, int count) {
  int i;
  qsort(entries, count, sizeof(ARangeEntry), compare_by_start);
  for (i = 1; i < count; ++i) {
    if (entries[i - 1].end > entries[i].start) {
/* This fires a lot.
      dwarf2_invalid_warning(obj, "ARange %lld-%lld overlaps with %lld-%lld, truncating",
                             (long long)entries[i - 1].start,
                             (long long)entries[i - 1].end,
                             (long long)entries[i].start,
                             (long long)entries[i].end); */
      entries[i - 1].end = entries[i].start;
    }
  }
  /* XXX should delete empty entries here */
  return safe_realloc(entries, count*sizeof(ARangeEntry));
}

static void build_aranges_unlocked(CH_DbgDwarf2Object* obj) {
  CH_GrowBuf buf;
  int count = 0;
  Elf_Data* data = obj->debug_aranges_data;
  uint8_t* ptr = data->d_buf;
  uint8_t* end = ptr + data->d_size;
  
  init_buf(&buf);
  
  while (ptr < end) {
    int is_aranges_64bit;
    int is_address_64bit;
    uint8_t segment_size;
    uint16_t version;
    CH_DbgDwarf2Offset len;
    CH_DbgDwarf2Offset cu_offset;
    uint8_t* next;
    
    if (!read_initial_length(obj, &ptr, end, &len, &is_aranges_64bit))
      break;
    next = ptr + len;
    if (next > end) {
      dwarf2_invalid_warning(obj, "Overrunning aranges data");
      break;
    }
    if (!read_uint16_t(obj, &ptr, next, &version))
      break;
    if (version != 2) {
      dwarf2_invalid_warning(obj, "Unknown aranges version %d", version);
      break;
    }
    if (!read_offset(obj, &ptr, next, &cu_offset, is_aranges_64bit))
      break;
    if (!read_address_size(obj, &ptr, next, &is_address_64bit))
      break;
    if (!read_uint8_t(obj, &ptr, next, &segment_size))
      break;
    if (segment_size != 0) {
      dwarf2_invalid_warning(obj, "Bad segment size %d, expected 0",
                             segment_size);
      break;
    }
    
    /* align to the size of a tuple, i.e., twice the size of an address */
    if (!align_bytes(obj, &ptr, next, is_address_64bit ? 16 : 8))
      break;

    for (;;) {
      uint64_t address;
      uint64_t length;
      ARangeEntry* entry;
      CH_Address start_addr, end_addr;
      if (!read_uword(obj, &ptr, next, &address, is_address_64bit)) {
        ptr = end;
        break;
      }
      if (!read_uword(obj, &ptr, next, &length, is_address_64bit)) {
        ptr = end;
        break;
      }
      
      if (!address && !length)
        break; /* normal termination of the set */

      if (address + length < address) {
        dwarf2_invalid_warning(obj,
                               "Address/length overflow, address=%lld, length=%lld; skipping",
                               (long long)address, (long long)length);
        continue;
      }
      if (!convert_64bit_offset(obj, address, &start_addr))
        continue;
      if (!convert_64bit_offset(obj, address + length, &end_addr))
        continue;

      if (start_addr > 0) {
        ensure_buffer_size(&buf, (count + 1)*sizeof(ARangeEntry));
        entry = (ARangeEntry*)buf.data + count;
        entry->start = start_addr;
        entry->end = end_addr;
        entry->compilation_unit = cu_offset;
        count++;
      }
    }
    
    ptr = next;
  }

  obj->aranges = sort_and_remove_overlaps(obj, (ARangeEntry*)buf.data, count);
  obj->num_aranges = count;
}

static CH_DbgDwarf2Offset find_compilation_unit_for_address(CH_DbgDwarf2Object* obj,
                                                            uint64_t dwarf_addr) {
  uint32_t start;
  uint32_t end;
  ARangeEntry* aranges;

  pthread_mutex_lock(&obj->arange_lock);
  if (obj->num_aranges < 0 && obj->debug_aranges_data) {
    build_aranges_unlocked(obj);
  }
  pthread_mutex_unlock(&obj->arange_lock);

  if (obj->num_aranges < 1)
    return 0;

  aranges = obj->aranges;
  start = 0;
  end = obj->num_aranges;
  while (end - start > 1) {
    uint32_t mid = (start + end)/2;
    if (aranges[mid].start <= dwarf_addr) {
      start = mid;
    } else {
      end = mid;
    }
  }

  if (aranges[start].start <= dwarf_addr && aranges[start].end > dwarf_addr)
    return aranges[start].compilation_unit;
  return 0;
}

static int find_address_in_range_list(CH_DbgDwarf2Object* obj,
    int is_address_64bit, uint64_t base_addr, uint64_t start_scope_offset,
    CH_DbgDwarf2Offset range_list, uint64_t dwarf_addr, int* found)
{
  uint8_t* ptr = (uint8_t*)obj->debug_ranges_data->d_buf + range_list;
  uint8_t* ptr_end = (uint8_t*)obj->debug_ranges_data->d_buf + obj->debug_ranges_data->d_size;
  
  for (;;) {
    uint64_t start, end;
    if (!read_uword(obj, &ptr, ptr_end, &start, is_address_64bit))
      return 0;
    if (!read_uword(obj, &ptr, ptr_end, &end, is_address_64bit))
      return 0;
    if (!start && !end) {
      *found = 0;
      return 1;
    }
    
    if (start == is_address_64bit ? (uint64_t)-1 : (uint32_t)-1) {
      /* this is a base address selection entry */
      base_addr = end;
    } else {
      if (base_addr + start + start_scope_offset <= dwarf_addr &&
          dwarf_addr < base_addr + end) {
        *found = 1;
        return 1;
      }
      /* start_scope only affects the first element of the range */
      start_scope_offset = 0;
    }
  }
}

static uint64_t get_cu_base_address(CompilationUnitReader* cu_reader) {
  if (cu_reader->base_address == (uint64_t)-1) {
    EntryReader reader;

    if (begin_reading_entry(cu_reader, cu_reader->first_entry, &reader) &&
        !reader.is_empty && reader.tag == DW_TAG_compile_unit) {
      uint64_t low;
      int found;
      if (!read_attribute_address(&reader, DW_AT_low_pc, &low, &found))
        return 0;
      if (found) {
        cu_reader->base_address = low;
      } else {
        /* XXX this is not specified in the Dwarf3 spec, but gcc seems to assume it */
        cu_reader->base_address = 0;
      }
    }
  }
      
  return cu_reader->base_address;
}

static int check_addr_in_entry_range(uint64_t addr, EntryReader* reader,
                                     uint64_t start_scope_offset,
                                     int default_in_range, int* in_range) {
  uint64_t low;
  int found;

  *in_range = default_in_range;

  if (!read_attribute_address(reader, DW_AT_low_pc, &low, &found))
    return 0;
  if (found) {
    uint64_t high;
    if (!read_attribute_address(reader, DW_AT_high_pc, &high, &found))
      return 0;
    if (found) {
      *in_range = low + start_scope_offset <= addr && addr < high;
    }
  } else {
    /* check for discontiguous ranges */
    CH_DbgDwarf2Offset range_list;
    CH_DbgDwarf2Object* obj = reader->cu_reader->obj;
    if (!read_attribute_listptr(reader, DW_AT_ranges, &range_list, &found))
      return 0;
    if (found && obj->debug_ranges_data) {
      uint64_t base_addr = get_cu_base_address(reader->cu_reader);
      if (base_addr == (uint64_t)-1)
        return 0;
      if (!find_address_in_range_list(obj, reader->cu_reader->is_address_64bit,
                                      base_addr, start_scope_offset, range_list,
                                      addr, &found))
        return 0;
      *in_range = found;
    }
  }
  return 1;
}

static int lookup_function_info(EntryReader* reader, CH_DbgDwarf2Offset info_offset,
    uint32_t flags, LineNumberTable* line_table, CH_DbgDwarf2FunctionInfo* info) {
  uint64_t result;
  int found;
  CH_StringBuf container_prefix;
  CH_StringBuf namespace_prefix;
  uint64_t raw_entry_point = 0;
  CH_DbgDwarf2Offset origin = 0;

  info->entry_point = 0;
  info->prologue_end = 0;
  info->type_offset = 0;
  info->name = NULL;
  info->container_prefix = NULL;
  info->namespace_prefix = NULL;
  
  if (!read_attribute_reference(reader, DW_AT_abstract_origin, &origin, &found))
    return 0;
  if (!found) {
    if (!read_attribute_reference(reader, DW_AT_specification, &origin, &found))
      return 0;
  }
  if (found) {
    EntryReader sub_reader;
    if (!begin_reading_entry(reader->cu_reader, origin, &sub_reader))
      return 0;
    if (!lookup_function_info(&sub_reader, origin, flags, line_table, info))
      return 0;
  }

  if (flags & DWARF2_FUNCTION_ADDRESS) {
    if (!read_attribute_address(reader, DW_AT_entry_pc, &result, &found))
      return 0;
    if (!found) {
      if (!read_attribute_address(reader, DW_AT_low_pc, &result, &found))
        return 0;
    }
    if (found) {
      raw_entry_point = result;
      if (!translate_dwarf_address_to_file_offset(reader->cu_reader->obj,
          result, &info->entry_point))
        return 0;
    }
  }
  
  if (flags & DWARF2_FUNCTION_TYPE) {
    if (!read_attribute_reference(reader, DW_AT_type, &info->type_offset, &found))
      return 0;
  }
  
  if ((flags & DWARF2_FUNCTION_PROLOGUE_END) && raw_entry_point) {
    /* This is really bogus. Dwarf2 has support for marking the end of function
       prologue, but gcc doesn't use it. gdb just assumes the first line number
       entry for a function is the prologue and the next one is the start of
       real code. */
    LineNumberEntry* entry = find_line_number_entry_for(line_table, raw_entry_point);
    if (entry &&
        entry + 1 < line_table->line_number_entries + line_table->line_number_entry_count) {
      uint64_t candidate = entry[1].address;
      int in_function;
      if (!check_addr_in_entry_range(candidate, reader, 0, 0, &in_function))
        return 0;
      if (in_function) {
        if (!translate_dwarf_address_to_file_offset(reader->cu_reader->obj,
            candidate, &info->prologue_end))
          return 0;
      }
    }
  }
  
  if (flags & DWARF2_FUNCTION_IDENTIFIER) {
    if (!read_attribute_string(reader, DW_AT_name, &info->name, &found))
      return 0;
      
    if (!lookup_compilation_unit_info(reader->cu_reader, &info->cu))
      return 0;
  
    stringbuf_init(&container_prefix);
    stringbuf_init(&namespace_prefix);
    if (!extract_prefixes(reader->cu_reader, &namespace_prefix, &container_prefix,
                          info_offset)) {
      stringbuf_destroy(&namespace_prefix);
      stringbuf_destroy(&container_prefix);
      return 0;
    }
  
    if (stringbuf_len(&container_prefix)) {
      info->container_prefix = stringbuf_finish(&container_prefix);
    }
    if (stringbuf_len(&namespace_prefix)) {
      info->namespace_prefix = stringbuf_finish(&namespace_prefix);
    }
  }
  
  return 1;
}

int dwarf2_lookup_function_info(QueryThread* q,
    CH_DbgDwarf2Object* obj, CH_DbgDwarf2Offset defining_object_offset,
    uint32_t flags, CH_DbgDwarf2FunctionInfo* info) {
  CH_DbgDwarf2Offset info_cu_offset =
    find_compilation_unit_offset_for(obj, defining_object_offset);
  CompilationUnitReader cu_reader;
  EntryReader reader;
  LineNumberTable line_table;
  int result;
  
  if (!read_debug_info_header(obj, info_cu_offset, &cu_reader))
    return 0;
  if (!begin_reading_entry(&cu_reader, defining_object_offset, &reader))
    return 0;
  if (reader.is_empty)
    return 0;

  if (flags & DWARF2_FUNCTION_PROLOGUE_END) {
    if (!get_line_number_table(q, &cu_reader, &line_table))
      return 0;
  }
  result = lookup_function_info(&reader, defining_object_offset, flags,
                                &line_table, info);
  if (flags & DWARF2_FUNCTION_PROLOGUE_END) {
    free_line_number_table(&line_table);
  }  
  return result;
}

int dwarf2_get_container_function(QueryThread* q, CH_DbgDwarf2Object* obj,
                                  CH_Address file_offset, CH_DbgDwarf2Offset* result) {
  uint64_t dwarf_addr;
  CH_DbgDwarf2Offset cu;
  CH_DbgDwarf2Offset entry;
  CompilationUnitReader cu_reader;

  if (!translate_file_offset_to_dwarf_address(obj, file_offset, &dwarf_addr))
    return 0;
  cu = find_compilation_unit_for_address(obj, dwarf_addr);
  if (!cu)
    return 0;

  if (!read_debug_info_header(obj, cu, &cu_reader))
    return 0;
  entry = cu_reader.first_entry;

  /* scan through all the entries in the compilation unit. */
  while (entry < cu_reader.entries_end) {
    EntryReader reader;
    if (!begin_reading_entry(&cu_reader, entry, &reader))
      return 0;
    if (!reader.is_empty && reader.tag == DW_TAG_subprogram) {
      int in_range;
      if (!check_addr_in_entry_range(dwarf_addr, &reader, 0, 0, &in_range))
        return 0;
      if (in_range) {
        *result = entry;
        return 1;
      }
    }
    entry = find_end_of_entry(&reader);
    if (!entry)
      return 0;
  }

  *result = 0;  
  return 1;
}

typedef struct {
  CH_DbgDwarf2Offset offset;
  CH_DbgDwarf2Offset final_offset;
  CH_DbgDwarf2Offset parent_offset;
  char const*        name;
  char const*        separator_before_child;

  CH_Address           address;
  CH_DbgCompletionKind kind;
  uint8_t              is_partial;
} GlobalSymbolPart;

typedef struct {
  CH_DbgDwarf2Offset offset;
  GlobalSymbolPart*  destination;
} GlobalSymbolForwarding;

typedef struct {
  CompilationUnitReader cu_reader;
  CH_GrowBuf            global_symbol_parts;
  CH_GrowBuf            global_symbol_forwardings;
  const char*           container_separator;
  uint32_t              global_symbol_parts_count;
  uint32_t              global_symbol_forwardings_count;
  uint32_t              global_symbol_count;
} LoadGlobalSymbolsParameters;

static GlobalSymbolPart* allocate_part(LoadGlobalSymbolsParameters* params) {
  ++params->global_symbol_parts_count;
  ensure_buffer_size(&params->global_symbol_parts,
                     sizeof(GlobalSymbolPart)*params->global_symbol_parts_count);
                     
  return (GlobalSymbolPart*)params->global_symbol_parts.data +
    params->global_symbol_parts_count - 1;
}

static void allocate_forwarding(LoadGlobalSymbolsParameters* params,
    uint32_t offset, GlobalSymbolPart* part) {
  GlobalSymbolForwarding* f;

  ++params->global_symbol_forwardings_count;
  ensure_buffer_size(&params->global_symbol_forwardings,
                     sizeof(GlobalSymbolForwarding)*params->global_symbol_forwardings_count);
                       
  f = (GlobalSymbolForwarding*)params->global_symbol_forwardings.data +
    params->global_symbol_forwardings_count - 1;
  f->offset = offset;
  f->destination = part;
}

static GlobalSymbolPart* lookup_forwarding(LoadGlobalSymbolsParameters* params,
    CH_DbgDwarf2Offset offset) {
  GlobalSymbolForwarding* forwardings =
    (GlobalSymbolForwarding*)params->global_symbol_forwardings.data;
  uint32_t start = 0, end = params->global_symbol_forwardings_count;
  while (end - start > 1) {
    uint32_t mid = (start + end)/2;
    if (forwardings[mid].offset <= offset) {
      start = mid;
    } else {
      end = mid;
    }
  }
  if (start >= end || forwardings[start].offset != offset) {
    dwarf2_invalid_warning(params->cu_reader.obj,
                           "Cannot find part for offset %d", offset);
    return NULL;
  }
  return forwardings[start].destination;
}

static GlobalSymbolPart* lookup_part(LoadGlobalSymbolsParameters* params,
    CH_DbgDwarf2Offset offset) {
  GlobalSymbolPart* parts = (GlobalSymbolPart*)params->global_symbol_parts.data;
  uint32_t start = 0, end = params->global_symbol_parts_count;
  while (end - start > 1) {
    uint32_t mid = (start + end)/2;
    if (parts[mid].offset <= offset) {
      start = mid;
    } else {
      end = mid;
    }
  }
  if (start >= end || parts[start].offset != offset)
    return lookup_forwarding(params, offset);
  return &parts[start];
}

static int lookup_part_for_specification(
    LoadGlobalSymbolsParameters* params, EntryReader* reader,
    GlobalSymbolPart** part) {
  CH_DbgDwarf2Offset ref;
  int found;

  if (!read_attribute_reference(reader, DW_AT_specification, &ref, &found))
    return 0;
  if (!found) {
    *part = NULL;
    return 1;
  }
  *part = lookup_part(params, ref);
  if (!*part)
    return 0;
  return 1;
}      

static int lookup_part_for_abstract_origin(
    LoadGlobalSymbolsParameters* params, EntryReader* reader,
    GlobalSymbolPart** part) {
  CH_DbgDwarf2Offset ref;
  int found;

  if (!read_attribute_reference(reader, DW_AT_abstract_origin, &ref, &found))
    return 0;
  if (!found) {
    *part = NULL;
    return 1;
  }
  *part = lookup_part(params, ref);
  if (!*part)
    return 0;
  return 1;
}      

static int load_global_symbols_recursive(LoadGlobalSymbolsParameters* params,
                                         CH_DbgDwarf2Offset entry_offset,
                                         EntryReader* reader,
                                         CH_DbgDwarf2Offset parent_offset) {
  switch (reader->tag) {
    case DW_TAG_subprogram: {
      GlobalSymbolPart* part;
      CH_DbgDwarf2FunctionInfo info;
      int found;
      int is_inline_instance = 0;

      if (!lookup_part_for_specification(params, reader, &part))
        return 0;
      if (!part) {
        if (!lookup_part_for_abstract_origin(params, reader, &part))
          return 0;
        if (part) {
          is_inline_instance = 1;
        }
      }
      
      if (part) {
        allocate_forwarding(params, entry_offset, part);
      } else {
        part = allocate_part(params);
        part->parent_offset = parent_offset;
        part->kind = AUTOCOMPLETE_KIND_GLOBAL_FUNCTION;
        part->separator_before_child = NULL;
        part->address = 0;
        part->name = NULL;
        part->is_partial = 1;
        params->global_symbol_count++;
        part->offset = entry_offset;
      }
      if (!is_inline_instance) {
        part->final_offset = entry_offset;
      }
      
      if (!read_attribute_flag(reader, DW_AT_declaration, &found))
        return 0;
      if (!found) {
        part->is_partial = 0;
      }

      if (!lookup_function_info(reader, entry_offset, DWARF2_FUNCTION_ADDRESS,
                                NULL, &info))
        return 0;
      if (info.entry_point) {
        part->address = info.entry_point;
      }
       
      /* If the name is present, allow it to fill in the name for the prior
         declaration. */
      return read_attribute_string(reader, DW_AT_name, &part->name, &found);
      /* Don't descend into children. There could be type definitions
         there, possibly even with interesting members, but it's not worth
         the cost of finding those rare declarations. */
    }
    
    case DW_TAG_variable:
      // TODO Fill this in! It's complicated by the fact that the address
      // might not be real (e.g., global variables can be placed in registers)
      return 1;
    
    case DW_TAG_compile_unit:
    case DW_TAG_namespace:
      /* descend into these entries using same parent */
      break;
    
    case DW_TAG_base_type:
    case DW_TAG_class_type:
    case DW_TAG_interface_type:
    case DW_TAG_structure_type:
    case DW_TAG_union_type: {
      int found;
      GlobalSymbolPart* part;
      uint64_t byte_size;

      if (!lookup_part_for_specification(params, reader, &part))
        return 0;
      
      if (part) {
        allocate_forwarding(params, entry_offset, part);
      } else {
        part = allocate_part(params);
        part->parent_offset = parent_offset;
        part->kind = AUTOCOMPLETE_KIND_GLOBAL_TYPE;
        part->address = 0;
        part->separator_before_child = params->container_separator;
        part->name = NULL;
        part->is_partial = 1;
        part->offset = entry_offset;
        params->global_symbol_count++;
      }
      part->final_offset = entry_offset;

      if (!read_attribute_flag(reader, DW_AT_declaration, &found))
        return 0;
      if (!found) {
        part->is_partial = 0;
      } else {
        if (!read_attribute_unsigned_constant(reader, DW_AT_byte_size, &byte_size, &found))
          return 0;
        if (found) {
          part->is_partial = 0;
        }
      }

      /* If the name is present, allow it to fill in the name for the prior
         declaration */
      if (!read_attribute_string(reader, DW_AT_name, &part->name, &found))
        return 0;
      
      /* descend into children using this parent */
      parent_offset = part->offset;
      break;
    }
    
    default:
      /* don't descend into this entry */
      return 1;
  }
  
  if (reader->has_children) {
    /* descend into this entry */
    CH_DbgDwarf2Offset child = find_end_of_entry(reader);
    for (;;) {
      EntryReader child_reader;
      if (!begin_reading_entry(&params->cu_reader, child, &child_reader))
        return 0;
      if (child_reader.is_empty)
        break;
      if (!load_global_symbols_recursive(params, child, &child_reader, parent_offset))
        return 0;
      child = find_end_of_entry_subtree(&child_reader);
    }
  }

  return 1;
}

/**
 * XXX we really need to rewrite this to uniquify constructed symbols via
 * a *global* hashtable. Right now we might construct the same text over and
 * over, and although debuginfo.c throws out duplicate symbols, it won't
 * release the allocated text memory.
 */
static int build_complete_symbol(LoadGlobalSymbolsParameters* params,
    GlobalSymbolPart* part, uint32_t kid_text_size,
    CH_GrowBuf* text_buf, uint32_t* text_buf_count) {
  uint32_t name_len = 0;
  uint32_t separator_len = 0;
  uint32_t required_size = kid_text_size;
  char* dest;
  
  if (part->name) {
    name_len = strlen(part->name);
    required_size += name_len;

    if (kid_text_size > 0) {
      if (!part->separator_before_child) {
        dwarf2_invalid_warning(params->cu_reader.obj,
          "Found nested declarations, but we don't know what the language uses "
          "for a separator");
        return 0;
      }
      separator_len = strlen(part->separator_before_child);
      required_size += separator_len;
    }
  }
  
  if (part->parent_offset) {
    GlobalSymbolPart* parent = lookup_part(params, part->parent_offset);
    if (!parent)
      return 0;
    if (!build_complete_symbol(params, parent, required_size, text_buf, text_buf_count))
      return 0;
  } else {
    *text_buf_count += required_size + 1;
    ensure_buffer_size(text_buf, *text_buf_count);
  }

  dest = (char*)text_buf->data + *text_buf_count - 1 - required_size;
  memcpy(dest, part->name, name_len);
  memcpy(dest + name_len, part->separator_before_child, separator_len);
  return 1;
}

/* Can be called on any thread; readonly */
void dwarf2_load_global_symbols(CH_DbgDwarf2Object* obj, DebugObject* obj_external) {
  /* We can't use pubnames/pubtypes because lots of important stuff (e.g.,
   * static functions) doesn't get put in there */
  LoadGlobalSymbolsParameters params;
  int i;
  CH_DbgGlobalSymbol* symbols;
  int32_t* symbol_text_buf_offsets;
  int sym_index;
  int sym_count;
  GlobalSymbolPart* parts;
  CH_GrowBuf text_buf;
  uint32_t text_buf_count = 0;
  
  init_buf(&params.global_symbol_parts);
  init_buf(&params.global_symbol_forwardings);
  params.global_symbol_parts_count = 0;
  params.global_symbol_forwardings_count = 0;
  params.global_symbol_count = 0;
  
  for (i = 0; i < obj->num_compilation_units; ++i) {
    CH_DbgDwarf2Offset cu = obj->debuginfo_compilation_unit_offsets[i];
    EntryReader first_reader;
    CH_Dwarf2_DW_LANG language;
    
    if (!read_debug_info_header(obj, cu, &params.cu_reader) ||
        !get_line_number_table(NULL, &params.cu_reader, NULL)) {
      safe_free(params.global_symbol_parts.data);
      safe_free(params.global_symbol_forwardings.data);
      return;
    }
    language = get_language(&params.cu_reader);
    if (language) {
      params.container_separator = get_container_separator(obj, language);
    } else {
      params.container_separator = NULL;
    }
    if (!begin_reading_first_entry(&params.cu_reader, &first_reader)) {
      safe_free(params.global_symbol_parts.data);
      safe_free(params.global_symbol_forwardings.data);
      return;
    }
    
    if (!load_global_symbols_recursive(&params, params.cu_reader.first_entry,
                                       &first_reader, 0)) {
      safe_free(params.global_symbol_parts.data);
      safe_free(params.global_symbol_forwardings.data);
      return;
    }
  }
  
  /* now we need to sweep over the parts and build the real symbols */

  symbols = safe_malloc(params.global_symbol_count*sizeof(CH_DbgGlobalSymbol));
  symbol_text_buf_offsets = safe_malloc(params.global_symbol_count*sizeof(uint32_t));
  sym_index = 0;
  parts = (GlobalSymbolPart*)params.global_symbol_parts.data;
  init_buf(&text_buf);
  for (i = 0; i < params.global_symbol_parts_count; ++i) {
    GlobalSymbolPart* part = &parts[i];
    if (part->kind && part->name &&
        (part->kind != AUTOCOMPLETE_KIND_GLOBAL_FUNCTION ||
         part->address > 0)) {
      CH_DbgGlobalSymbol* sym = &symbols[sym_index];
      sym->address = part->address;
      sym->kind = part->kind;
      sym->is_partial = part->is_partial;
      sym->defining_object_offset = part->final_offset;
      if (part->parent_offset == 0) {
        sym->name = part->name;
        symbol_text_buf_offsets[sym_index] = -1;
      } else {
        sym->name = NULL;
        symbol_text_buf_offsets[sym_index] = text_buf_count;
        build_complete_symbol(&params, part, 0, &text_buf, &text_buf_count);
        text_buf.data[text_buf_count - 1] = 0;
      }
      sym_index++;
    }
  }
  safe_free(params.global_symbol_parts.data);
  safe_free(params.global_symbol_forwardings.data);

  /* the symbol count can shrink because load_global_symbols_recursive does not
     know, when it sets params.global_symbol_count, which symbols will end up
     with names (names can be added late via DW_AT_specification). The above
     loop skips the anonymous symbols. */
  sym_count = sym_index;
  symbols = safe_realloc(symbols, sym_count*sizeof(CH_DbgGlobalSymbol));

  for (sym_index = 0; sym_index < sym_count; ++sym_index) {
    int32_t text_offset = symbol_text_buf_offsets[sym_index];
    if (text_offset >= 0) {
      symbols[sym_index].name = (char*)text_buf.data + text_offset;
    }
  }
  safe_free(symbol_text_buf_offsets);

  obj->globals_text = (char*)text_buf.data;
  /* the globals text lives forever, but we may as well keep a pointer to it
     to keep leak detectors happy */

  dbg_add_global_symbols(sym_count, obj_external, symbols);
}

static CH_DbgDwarf2VariableInfo* allocate_variable(CH_GrowBuf* buf, uint32_t* count) {
  ++*count;
  ensure_buffer_size(buf, *count * sizeof(CH_DbgDwarf2VariableInfo));
  return (CH_DbgDwarf2VariableInfo*)buf->data + *count - 1;
}

static int fill_in_variable_info(EntryReader* reader,
                                 CH_DbgDwarf2Offset child_offset,
                                 CH_DbgDwarf2VariableInfo* info) {
  int found;
  CH_DbgDwarf2Offset ref;

  if (!read_attribute_reference(reader, DW_AT_specification, &ref, &found))
    return 0;
  if (found) {
    EntryReader spec_reader;
    if (!begin_reading_entry(reader->cu_reader, ref, &spec_reader))
      return 0;
    if (!fill_in_variable_info(&spec_reader, ref, info))
      return 0;
  }
  
  if (!read_attribute_reference(reader, DW_AT_abstract_origin, &ref, &found))
    return 0;
  if (found) {
    EntryReader origin_reader;
    if (!begin_reading_entry(reader->cu_reader, ref, &origin_reader))
      return 0;
    if (!fill_in_variable_info(&origin_reader, ref, info))
      return 0;
  }
  
  if (!read_attribute_string(reader, DW_AT_name, &info->name, &found))
    return 0;
  if (!read_attribute_reference(reader, DW_AT_type, &info->type_offset, &found))
    return 0;

  if (!read_attribute_flag(reader, DW_AT_artificial, &found))
    return 0;
  if (found) {
    info->is_synthetic = 1;
  }

  return 1;
}

static int get_variables_children(EntryReader* reader, CH_Dwarf2_DW_TAG tag,
    uint64_t pc_addr, EntryReader* enclosing_scope, int* param_index,
    CH_GrowBuf* result, uint32_t* count) {
  CH_DbgDwarf2Offset child_offset = find_end_of_entry(reader);

  for (;;) {
    EntryReader child_reader;
  
    if (!child_offset)
      return 0;
    if (!begin_reading_entry(reader->cu_reader, child_offset, &child_reader))
      return 0;
    if (child_reader.is_empty)
      return 1;

    if (child_reader.tag == tag) {
      CH_DbgDwarf2VariableInfo* info;
      uint64_t start_scope;
      int found;
      int in_range = 1;
      
      /* check to see whether this variable is in scope */
      if (!read_attribute_unsigned_constant(&child_reader, DW_AT_start_scope,
                                            &start_scope, &found))
        return 0;
      if (found) {
        if (!check_addr_in_entry_range(pc_addr, enclosing_scope, start_scope,
                                       1, &in_range))
          return 0;
      }

      if (in_range) {
        if (tag == DW_TAG_formal_parameter && *param_index < *count) {
          /* It's a formal parameter that we've seen before, so just fill
             in its entry some more. */
          info = (CH_DbgDwarf2VariableInfo*)result->data + *param_index;
        } else {
          info = allocate_variable(result, count);
          info->name = NULL;
          info->type_offset = 0;
          info->is_synthetic = 0;
        }
        /* Note that concrete function instances are visited after inline
           abstractions or declarations, so favour the concrete function instance
           when storing the debuginfo offset for variable access. */
        info->variable_offset = child_offset;
        if (!fill_in_variable_info(&child_reader, child_offset, info))
          return 0;
      }
      
      ++(*param_index);
    } else {
      switch (child_reader.tag) {
        case DW_TAG_lexical_block:
        case DW_TAG_with_stmt:
        case DW_TAG_try_block:
        case DW_TAG_catch_block: {
          int in_range;
          /* descend into this entry if our pc is in the scope */
          if (!check_addr_in_entry_range(pc_addr, &child_reader, 0, 1,
                                         &in_range))
            return 0;
          if (in_range) {
            if (!get_variables_children(&child_reader, tag, pc_addr, &child_reader,
                                        param_index, result, count))
              return 0;
          }
          break;
        }
          
        case DW_TAG_namespace:
          /* descend into this entry */
          if (!get_variables_children(&child_reader, tag, pc_addr, enclosing_scope,
                                      param_index, result, count))
            return 0;
          break;

        default:
          break;
      }
    }
      
    child_offset = find_end_of_entry_subtree(&child_reader);
  }
}

static int get_variables_for_function(EntryReader* reader,
                                      uint64_t pc_addr, CH_Dwarf2_DW_TAG tag,
                                      CH_GrowBuf* result, uint32_t* variable_count) {
  CH_DbgDwarf2Offset origin = 0;
  int found;
  int param_index;

  if (!read_attribute_reference(reader, DW_AT_abstract_origin, &origin, &found))
    return 0;
  if (!found) {
    if (!read_attribute_reference(reader, DW_AT_specification, &origin, &found))
      return 0;
  }
  if (found) {
    EntryReader origin_reader;
    if (!begin_reading_entry(reader->cu_reader, origin, &origin_reader))
      return 0;
    if (!get_variables_for_function(&origin_reader, pc_addr, tag, result, variable_count))
      return 0;
  }

  if (!reader->has_children)
    return 1;
  param_index = 0;
  return get_variables_children(reader, tag, pc_addr, reader, &param_index, result,
                                variable_count);
}

static CH_DbgDwarf2VariableInfo* get_variables(CH_DbgDwarf2Object* obj,
                                               CH_DbgDwarf2Offset owner_offset,
                                               uint64_t pc_addr,
                                               CH_Dwarf2_DW_TAG tag) {
  CH_DbgDwarf2Offset info_cu_offset =
    find_compilation_unit_offset_for(obj, owner_offset);
  CompilationUnitReader cu_reader;
  EntryReader reader;
  CH_GrowBuf result;
  uint32_t variable_count = 0;
  CH_DbgDwarf2VariableInfo* last;
  
  if (!read_debug_info_header(obj, info_cu_offset, &cu_reader))
    return NULL;
  if (!begin_reading_entry(&cu_reader, owner_offset, &reader))
    return NULL;
  if (reader.is_empty)
    return NULL;
  init_buf(&result);
  if (!get_variables_for_function(&reader, pc_addr, tag, &result, &variable_count)) {
    safe_free(result.data);
    return NULL;
  }
  last = allocate_variable(&result, &variable_count);
  last->name = NULL;
  last->type_offset = last->variable_offset = 0;
  return safe_realloc(result.data, variable_count*sizeof(CH_DbgDwarf2VariableInfo));
}

CH_DbgDwarf2VariableInfo* dwarf2_get_variables(QueryThread* q, CH_DbgDwarf2Object* obj,
                                               CH_DbgDwarf2Offset container_offset,
                                               CH_Address pc_addr,
                                               CH_DbgDwarf2VariableKind kind) {
  uint64_t dwarf_pc_addr;
  CH_Dwarf2_DW_TAG tag = kind == CH_DWARF2_FORMAL_PARAMETER
    ? DW_TAG_formal_parameter : DW_TAG_variable;

  if (!translate_file_offset_to_dwarf_address(obj, pc_addr, &dwarf_pc_addr))
    return NULL;
  return get_variables(obj, container_offset, dwarf_pc_addr, tag);
}

typedef struct {
  uint64_t start;
  uint64_t length;
} CH_Range64;

static int search_location_list(CompilationUnitReader* cu_reader,
  uint64_t pc_addr, CH_DbgDwarf2Offset offset,
  uint8_t** data, uintptr_t* size, CH_Range64** valid_instruction_ranges) {
  CH_DbgDwarf2Object* obj = cu_reader->obj;
  Elf_Data* elf_data = obj->debug_loc_data;
  uint8_t* ptr;
  uint8_t* ptr_end;
  uint64_t base_addr = get_cu_base_address(cu_reader);
  
  if (!elf_data) {
    dwarf2_invalid_warning(obj, "No .debug_loc section found");
    return 0;
  }

  ptr = elf_data->d_buf + offset;
  ptr_end = ptr + elf_data->d_size;

  for (;;) {
    uint64_t start, end;
    
    if (!read_uword(obj, &ptr, ptr_end, &start, cu_reader->is_address_64bit))
      return 0;
    if (!read_uword(obj, &ptr, ptr_end, &end, cu_reader->is_address_64bit))
      return 0;
    if (!start && !end) {
      *data = NULL;
      *valid_instruction_ranges = NULL;
      return 1;
    }
    
    if (start == (cu_reader->is_address_64bit ? (uint64_t)-1 : (uint32_t)-1)) {
      /* this is a base address selection entry */
      base_addr = end;
    } else {
      uint16_t len;
      if (!read_uint16_t(obj, &ptr, ptr_end, &len))
        return 0;

      if (base_addr == (uint64_t)-1)
        return 0;

      if (base_addr + start <= pc_addr && pc_addr < base_addr + end) {
        CH_Range64* valid_ranges = malloc(sizeof(CH_Range64)*2);
        *data = ptr;
        *size = len;
        valid_ranges[0].start = base_addr + start;
        valid_ranges[0].length = end - start;
        valid_ranges[1].start = 0;
        valid_ranges[1].length = 0;
        *valid_instruction_ranges = valid_ranges;
        return 1;
      }
    
      ptr += len;
    }
  }
}

static int find_location_expression(EntryReader* reader,
  CH_Dwarf2_DW_AT attribute, uint64_t pc_addr, uint8_t** data, uintptr_t* size,
  CH_Range64** valid_instruction_ranges) {
  uint8_t* attr_data;
  CH_Dwarf2_DW_FORM form;
  CH_DbgDwarf2Object* obj = reader->cu_reader->obj;

  if (!find_attribute(reader, attribute, &attr_data, &form))
    return 0;
    
  if (form == 0) {
    int found;
    CH_DbgDwarf2Offset origin;
    if (!read_attribute_reference(reader, DW_AT_abstract_origin, &origin, &found))
      return 0;
    if (!found) {
      if (!read_attribute_reference(reader, DW_AT_specification, &origin, &found))
        return 0;
    }
    if (found) {
      EntryReader sub_reader;
      if (!begin_reading_entry(reader->cu_reader, origin, &sub_reader))
        return 0;
      return find_location_expression(&sub_reader, attribute, pc_addr, data, size,
                                      valid_instruction_ranges);
    }
    /* no value for this variable */
    *data = NULL;
    *valid_instruction_ranges = NULL;
    return 1;
  }

  switch (form) {
    case DW_FORM_block1:
    case DW_FORM_block2:
    case DW_FORM_block4:
    case DW_FORM_block: {
      *valid_instruction_ranges = NULL;
      *data = get_block(obj, attr_data, reader->entry_end, form, size);
      return *data != NULL;
    }

    case DW_FORM_data4:
    case DW_FORM_data8: {
      uint64_t offset;
      CH_DbgDwarf2Offset dwarf_offset;
      if (!read_uword(obj, &attr_data, reader->entry_end, &offset, form == DW_FORM_data8))
        return 0;
      if (!convert_64bit_offset(obj, offset, &dwarf_offset))
        return 0;

      return search_location_list(reader->cu_reader, pc_addr, dwarf_offset,
                                  data, size, valid_instruction_ranges);
    }

    default:
      dwarf2_invalid_warning(obj, "Bad location form: %d", form);
      return 0;
  }
}

/******** DWARF2 EXPRESSION INTERPRETER *********/

#define DWARF2_INTERPRETER_MAX_WORK_STACK_SIZE 1024
#define DWARF2_INTERPRETER_MAX_OPERATION_COUNT 10240
#define DWARF2_INTERPRETER_MAX_CALL_STACK_SIZE 50

typedef struct {
  CH_DbgDwarf2Object*    obj;
  CompilationUnitReader* cu_reader;
  EntryReader*           context_reader;
  CH_DbgProgramState*    state;
  uint64_t               pc_addr;
  
  CH_GrowBuf stack;
  uintptr_t  stack_count;
  int64_t    stacked_register;
  
  CH_GrowBuf pieces;
  uintptr_t  piece_count;
  
  CH_Range64* validity_range;
  int         is_OK;
  int         is_program_state_error;
  int         operation_count;
  int         call_depth;
  int         has_object_base_address;
  uint64_t    object_base_address;
  uint8_t     addr_size;
} Dwarf2ExprInterpreter;

static void interpreter_push(Dwarf2ExprInterpreter* interp, uint64_t value) {
  if (!interp->is_OK)
    return;

  if (interp->stack_count > DWARF2_INTERPRETER_MAX_WORK_STACK_SIZE) {
    dwarf2_invalid_warning(interp->obj,
                           "Stack size exceeded in Dwarf2 expression");
    interp->is_OK = 0;
    return;
  }
  
  ensure_buffer_size(&interp->stack, (interp->stack_count + 1)*sizeof(CH_Address));
  if (value != (CH_Address)value) {
    dwarf2_invalid_warning(interp->obj,
                           "Width overflow in Dwarf2 expression");
    interp->is_OK = 0;
    return;
  }

  ((CH_Address*)interp->stack.data)[interp->stack_count] = value;
  interp->stack_count++;
}

static CH_Address interpreter_pop(Dwarf2ExprInterpreter* interp) {
  if (!interp->is_OK)
    return 0;

  if (interp->stack_count == 0) {
    dwarf2_invalid_warning(interp->obj,
                           "Stack underflow in Dwarf2 expression");
    interp->is_OK = 0;
    return 0;
  }

  --interp->stack_count;
  return ((CH_Address*)interp->stack.data)[interp->stack_count];
}

/* Initialize a location expression interpreter for a given program state.
 * @param context_reader gives the context to look up "frame pointer"
 * information for; can be NULL
 * @param state can be NULL if we have no program state. In that case, if the
 * interpreter ever needs program state, it will set is_program_state_error
 * and abort.
 * @param pc_addr the current program counter, if known; used to look up
 * location lists when a frame pointer expression is looked up. Will not be
 * used if context_reader is NULL.
 * @param basic_expression_validity a set of PC ranges for which the
 * expression is valid. This set can be restricted during evalution as the
 * interpreter looks up other DWARF expressions which are only valid for
 * a subset of PCs.
 */
static void interpreter_init(Dwarf2ExprInterpreter* interp,
    CompilationUnitReader* cu_reader, EntryReader* context_reader, CH_DbgProgramState* state,
    CH_Range64* basic_expression_validity, uint64_t pc_addr) {
  interp->obj = cu_reader->obj;
  interp->cu_reader = cu_reader;
  interp->context_reader = context_reader;
  interp->pc_addr = pc_addr;
  interp->state = state;
  init_buf(&interp->stack);
  interp->stack_count = 0;
  interp->stacked_register = -1;
  init_buf(&interp->pieces);
  interp->piece_count = 0;
  interp->validity_range = basic_expression_validity;
  interp->is_program_state_error = 0;
  interp->is_OK = 1;
  interp->addr_size = cu_reader->is_address_64bit ? 8 : 4;
  interp->operation_count = 0;
  interp->call_depth = 0;
  interp->has_object_base_address = 0;
}

static void interpreter_destroy(Dwarf2ExprInterpreter* interp) {
  safe_free(interp->stack.data);
  safe_free(interp->pieces.data);
  safe_free(interp->validity_range);
}

static CH_Address read_address_from_reg(Dwarf2ExprInterpreter* interp,
    uint8_t reg) {
  uint8_t buffer[8];
  uint64_t val;
  uint8_t* buf = buffer;
  
  if (interp->state == NULL) {
    interp->is_program_state_error = 1;
    return 0;
  }

  if (!dbg_read_reg(interp->state, reg,
                    interp->cu_reader->is_address_64bit ? 8 : 4, buffer)) {
    interp->is_OK = 0;
    return 0;
  }
  if (!read_uword(interp->obj, &buf, buffer + 8, &val,
                  interp->cu_reader->is_address_64bit)) {
    interp->is_OK = 0;
    return 0;
  }
  return (CH_Address)val;
}

static CH_Address read_address_from_memory(Dwarf2ExprInterpreter* interp,
    CH_Address addr, int size) {
  uint8_t buffer[8];
  uint8_t valid[8];
  uint64_t val;
  int i;
  uint8_t* buf = buffer;

  if (interp->state == NULL) {
    interp->is_program_state_error = 1;
    return 0;
  }

  memset(buffer, 0, sizeof(buffer));
  if (!dbg_read_memory(interp->state, addr, size, buffer, valid)) {
    interp->is_OK = 0;
    return 0;
  }
  for (i = 0; i < size; ++i) {
    if (!valid[i]) {
      interp->is_program_state_error = 1;
    }
  }
  /* XXX assumes little-endian */
  if (!read_uword(interp->obj, &buf, buffer + 8, &val,
                  interp->cu_reader->is_address_64bit)) {
    interp->is_OK = 0;
    return 0;
  }
  return (CH_Address)val;
}

#define NUM_ELEM(a) (sizeof(a)/sizeof(a[0]))

/* see gdb's amd64-tdep.c */
static int8_t AMD64_ABI_registers[] = {
  CH_X86_AX, CH_X86_DX, CH_X86_CX, CH_X86_BX,
  CH_X86_SI, CH_X86_DI, CH_X86_BP, CH_X86_SP,
  8, 9, 10, 11, 12, 13, 14, 15,
  CH_REG_PC,
  CH_X86_SSE_REGS, CH_X86_SSE_REGS + 1, CH_X86_SSE_REGS + 2, CH_X86_SSE_REGS + 3,
  CH_X86_SSE_REGS + 4, CH_X86_SSE_REGS + 5, CH_X86_SSE_REGS + 6, CH_X86_SSE_REGS + 7,
  CH_X86_SSE_REGS + 8, CH_X86_SSE_REGS + 9, CH_X86_SSE_REGS + 10, CH_X86_SSE_REGS + 11,
  CH_X86_SSE_REGS + 12, CH_X86_SSE_REGS + 13, CH_X86_SSE_REGS + 14, CH_X86_SSE_REGS + 15,
  -3, -3, -3, -3, -3, -3, -3, -3 /* floating point registers not simple */
};

/* see gdb's i386-tdep.c */
static int8_t X86_SYSV_ABI_registers[] = {
  CH_X86_AX, CH_X86_CX, CH_X86_DX, CH_X86_BX,
  CH_X86_SP, CH_X86_BP, CH_X86_SI, CH_X86_DI,
  CH_REG_PC,
  -2, /* eflags not supported */
  -2, -2, -2, -2, -2, -2, /* segment registers not supported */
  -3, -3, -3, -3, -3, -3, -3, -3, /* floating point registers not simple */
  -2, -2, -2, -2, -2, -2, -2, -2, /* floating point flags not supported */
  CH_X86_SSE_REGS, CH_X86_SSE_REGS + 1, CH_X86_SSE_REGS + 2, CH_X86_SSE_REGS + 3,
  CH_X86_SSE_REGS + 4, CH_X86_SSE_REGS + 5, CH_X86_SSE_REGS + 6, CH_X86_SSE_REGS + 7
};

/* Translate an X87 ST(0) ... ST(7) register into an AM register. This requires
   us to look at the current fptop. */
static int translate_x87_fpreg(Dwarf2ExprInterpreter* interp, uint8_t st_reg) {
  uint8_t fptop;
  if (!dbg_read_reg(interp->state, CH_X86_FPTOP_REG, 1, &fptop))
    return 0;
  return CH_X86_FP_REGS + ((fptop + st_reg)&7);
}

static int translate_dwarf2_reg(Dwarf2ExprInterpreter* interp, uint64_t reg) {
  CH_DbgDwarf2Object* obj = interp->obj;
  switch (obj->elf_machine_type) {
    case EM_X86_64: {
      int r;
      if (reg >= NUM_ELEM(AMD64_ABI_registers)) {
        dwarf2_invalid_warning(obj,
                               "Unsupported Dwarf2 register %d", reg);
        return -1;
      }
      r = AMD64_ABI_registers[reg];
      if (r != -3)
        return r;
      return translate_x87_fpreg(interp, (uint8_t)(reg - 24));
    }
    
    case EM_386: {
      int r;
      if (obj->elf_ABI != ELFOSABI_SYSV) {
        dwarf2_invalid_warning(obj,
                               "Unknown ABI type for expression registers: %d",
                               obj->elf_ABI);
        return -1;
      }
      if (reg >= NUM_ELEM(X86_SYSV_ABI_registers)) {
        dwarf2_invalid_warning(obj,
                               "Unsupported Dwarf2 register %d", reg);
        return -1;
      }
      r = X86_SYSV_ABI_registers[reg];
      if (r != -3)
        return r;
      return translate_x87_fpreg(interp, (uint8_t)(reg - 16));
    }
    
    default:
      dwarf2_invalid_warning(obj,
                             "Unknown machine type for expression registers: %d",
                             obj->elf_machine_type);
      return -1;
  }
}

static CH_Address read_address_from_dwarf2_reg(Dwarf2ExprInterpreter* interp,
    uint64_t reg) {
  int r = translate_dwarf2_reg(interp, reg);
  if (r < 0 || r > 255) {
    if (r != -1) {
      dwarf2_invalid_warning(interp->obj,
                             "Register %d does not hold addresses", reg);
    }
    interp->is_OK = 0;
    return 0;
  }
  return read_address_from_reg(interp, r);
}

static CH_DbgValuePiece* interpret_location_list(Dwarf2ExprInterpreter* interp,
  EntryReader* variable_reader, CH_Dwarf2_DW_AT attribute, int take_pieces);

static CH_Address read_fbreg_address(Dwarf2ExprInterpreter* interp) {
  CH_Address addr;
  Dwarf2ExprInterpreter subinterp;
  CH_DbgValuePiece* pieces;
  
  if (interp->context_reader == NULL) {
    dwarf2_invalid_warning(interp->obj,
      "A DWARF expression requests fbreg outside of a function context");
    interp->is_OK = 0;
    return 0;
  }
  
  interpreter_init(&subinterp, interp->cu_reader, interp->context_reader, interp->state,
                   interp->validity_range, interp->pc_addr);
  subinterp.call_depth = interp->call_depth + 1;
  subinterp.operation_count = interp->operation_count;
  pieces =
    interpret_location_list(&subinterp, interp->context_reader, DW_AT_frame_base, 1);
  
  interp->validity_range = subinterp.validity_range;
  interp->operation_count = subinterp.operation_count;
  subinterp.validity_range = NULL;
  interpreter_destroy(&subinterp);
  
  if (!pieces) {
    interp->is_OK = 0;
    return 0;
  }

  switch (pieces[0].type) {
    case CH_PIECE_REGISTER:
      addr = read_address_from_reg(interp, (uint32_t)pieces[0].source);
      break;
    case CH_PIECE_MEMORY:
      addr = pieces[0].source;
      break;
    case CH_PIECE_ERROR:
      /* propagate errors */
      interp->is_program_state_error = 1;
      addr = 0;
      break;
    default:
      interp->is_OK = 0;
      dwarf2_invalid_warning(interp->obj,
                             "Bad frame base in fbreg expression (%d)", pieces[0].type);
      safe_free(pieces);
      return 0;
  }
  
  if (pieces[0].source_offset_bits != 0 ||
      pieces[1].type != CH_PIECE_END ||
      (pieces[0].source_size_bits != 0 &&
       pieces[0].source_size_bits != (interp->cu_reader->is_address_64bit ? 64 : 32))) {
    interp->is_OK = 0;
    dwarf2_invalid_warning(interp->obj,
                           "Multi-part frame base in fbreg expression");
    addr = 0;
  }
  safe_free(pieces);
  return addr;
}

#define DWARF2_UNARY_OP(e) \
  { CH_SignedAddress v = interpreter_pop(interp); interpreter_push(interp, e); break; }
#define DWARF2_BINARY_OP(e) \
  { CH_SignedAddress v1 = interpreter_pop(interp); CH_SignedAddress v2 = interpreter_pop(interp); \
    interpreter_push(interp, e); break; }

static void interp_do_call(Dwarf2ExprInterpreter* interp, uint32_t offset) {
  EntryReader reader;
  
  if (!interp->is_OK)
    return;
  
  if (!begin_reading_entry(interp->cu_reader, offset, &reader)) {
    interp->is_OK = 0;
    return;
  }
  interpret_location_list(interp, &reader, DW_AT_location, 0);
}

/* when this gets called, 'interp' should have processed a simple location
   expression. */
static void interp_make_piece(Dwarf2ExprInterpreter* interp,
    int offset_bits, int size_bits) {
  CH_DbgValuePiece* piece;
  int total_stack_count = interp->stack_count + (interp->stacked_register >= 0);
  
  if (!interp->is_OK)
    return;
  
  if (total_stack_count > 1) {
    dwarf2_invalid_warning(interp->obj,
                           "Assembling a piece with multiple elements available on stack");
    interp->is_OK = 0;
    return;
  }
  if (interp->operation_count != 0 && total_stack_count == 0) {
    dwarf2_invalid_warning(interp->obj,
                           "Non-empty simple expression left nothing on stack");
    interp->is_OK = 0;
    return;
  }
  
  ensure_buffer_size(&interp->pieces,
                     (interp->piece_count + 1)*sizeof(CH_DbgValuePiece));
  piece = (CH_DbgValuePiece*)interp->pieces.data + interp->piece_count;
  
  if (interp->is_program_state_error) {
    piece->type = CH_PIECE_ERROR;
  } else if (interp->operation_count == 0) {
    piece->type = CH_PIECE_UNDEFINED;
  } else if (interp->stacked_register >= 0) {
    int src = translate_dwarf2_reg(interp, interp->stacked_register);
    if (src < 0) {
      interp->is_OK = 0;
      dwarf2_invalid_warning(interp->obj,
                             "Bad register %d", interp->stacked_register);
      return;
    }
    
    piece->type = CH_PIECE_REGISTER;
    piece->source = src;
  } else {
    piece->type = CH_PIECE_MEMORY;
    piece->source = interpreter_pop(interp);
  }
  piece->source_offset_bits = offset_bits;
  piece->source_size_bits = size_bits;
  
  /* reset interpreter state */
  interp->stacked_register = -1;
  interp->stack_count = 0;
  interp->is_program_state_error = 0;
  interp->operation_count = 0;
  interp->piece_count++;
}

static void interpreter_run(Dwarf2ExprInterpreter* interp,
    uint8_t* expr, uintptr_t expr_size) {
  uint8_t* expr_begin = expr;
  uint8_t* expr_end = expr + expr_size;
  
  if (interp->call_depth > DWARF2_INTERPRETER_MAX_CALL_STACK_SIZE) {
    dwarf2_invalid_warning(interp->obj,
                           "Call stack too deep in evaluation of Dwarf2 expression");
    interp->is_OK = 0;
    return;
  }

  while (interp->is_OK) {
    CH_Dwarf2_DW_OP op;
    
    if (expr == expr_end)
      break;
    
    if (expr < expr_begin || expr > expr_end) {
      dwarf2_invalid_warning(interp->obj,
                             "Expression code pointer went out of bounds");
      interp->is_OK = 0;
      break;
    }
    if (interp->operation_count > DWARF2_INTERPRETER_MAX_OPERATION_COUNT) {
      dwarf2_invalid_warning(interp->obj,
                             "Too many operations executed in evaluation of Dwarf2 expression");
      interp->is_OK = 0;
      break;
    }
    
    op = expr[0];
    expr++;
    
    if (interp->stacked_register >= 0 &&
        (op != DW_OP_piece && op != DW_OP_bit_piece)) {
      dwarf2_invalid_warning(interp->obj,
                             "regXX opcode was followed by some operator %d", op);
      interp->is_OK = 0;
      break;
    }
    
    switch (op) {
      case DW_OP_addr: {
        uint64_t addr = 0;
        interp->is_OK = read_uword(interp->obj, &expr, expr_end, &addr,
                                   interp->cu_reader->is_address_64bit);
        interpreter_push(interp, addr);
        break;
      }
      
      case DW_OP_const1u: {
        uint8_t c = 0;
        interp->is_OK = read_uint8_t(interp->obj, &expr, expr_end, &c);
        interpreter_push(interp, c);
        break;
      }
      case DW_OP_const1s: {
        uint8_t c = 0;
        interp->is_OK = read_uint8_t(interp->obj, &expr, expr_end, &c);
        interpreter_push(interp, (int8_t)c);
        break;
      }
      case DW_OP_const2u: {
        uint16_t c = 0;
        interp->is_OK = read_uint16_t(interp->obj, &expr, expr_end, &c);
        interpreter_push(interp, c);
        break;
      }
      case DW_OP_const2s: {
        uint16_t c = 0;
        interp->is_OK = read_uint16_t(interp->obj, &expr, expr_end, &c);
        interpreter_push(interp, (int16_t)c);
        break;
      }
      case DW_OP_const4u: {
        uint32_t c = 0;
        interp->is_OK = read_uint32_t(interp->obj, &expr, expr_end, &c);
        interpreter_push(interp, c);
        break;
      }
      case DW_OP_const4s: {
        uint32_t c = 0;
        interp->is_OK = read_uint32_t(interp->obj, &expr, expr_end, &c);
        interpreter_push(interp, (int32_t)c);
        break;
      }
      case DW_OP_const8u: {
        uint64_t c = 0;
        interp->is_OK = read_uint64_t(interp->obj, &expr, expr_end, &c);
        interpreter_push(interp, c);
        break;
      }
      case DW_OP_const8s: {
        uint64_t c = 0;
        interp->is_OK = read_uint64_t(interp->obj, &expr, expr_end, &c);
        interpreter_push(interp, (int64_t)c);
        break;
      }
      case DW_OP_constu: {
        uint64_t c = 0;
        interp->is_OK = read_uLEB128(interp->obj, &expr, expr_end, &c);
        interpreter_push(interp, c);
        break;
      }
      case DW_OP_consts: {
        int64_t c = 0;
        interp->is_OK = read_LEB128(interp->obj, &expr, expr_end, &c);
        interpreter_push(interp, c);
        break;
      }
      
      case DW_OP_fbreg: {
        CH_Address addr = read_fbreg_address(interp);
        if (interp->is_OK) {
          int64_t c = 0;
          interp->is_OK = read_LEB128(interp->obj, &expr, expr_end, &c);
          addr += c;
        }
        interpreter_push(interp, addr);
        break;
      }
      
      case DW_OP_bregx: {
        uint64_t reg;
        interp->is_OK = read_uLEB128(interp->obj, &expr, expr_end, &reg);
        if (interp->is_OK) {
          int64_t c;
          interp->is_OK = read_LEB128(interp->obj, &expr, expr_end, &c);
          if (interp->is_OK) {
            CH_Address addr = read_address_from_dwarf2_reg(interp, reg);
            interpreter_push(interp, addr + c);
          }
        }
        break;
      }
        
      case DW_OP_dup: {
        CH_Address v = interpreter_pop(interp);
        interpreter_push(interp, v);
        interpreter_push(interp, v);
        break;
      }
      case DW_OP_drop:
        interpreter_pop(interp);
        break;
      case DW_OP_pick: {
        uint8_t c = 0;
        interp->is_OK = read_uint8_t(interp->obj, &expr, expr_end, &c);
        if (interp->is_OK) {
          if (c >= interp->stack_count) {
            dwarf2_invalid_warning(interp->obj,
                                   "Bad pick index %d", c);
            interp->is_OK = 0;
          } else {
            interpreter_push(interp,
              ((CH_Address*)interp->stack.data)[interp->stack_count - 1 - c]);
          }
        }
        break;
      }
      case DW_OP_over: {
        CH_Address v1 = interpreter_pop(interp);
        CH_Address v2 = interpreter_pop(interp);
        interpreter_push(interp, v2);
        interpreter_push(interp, v1);
        interpreter_push(interp, v2);
        break;
      }
      case DW_OP_swap: {
        CH_Address v1 = interpreter_pop(interp);
        CH_Address v2 = interpreter_pop(interp);
        interpreter_push(interp, v1);
        interpreter_push(interp, v2);
        break;
      }
      case DW_OP_rot: {
        CH_Address v1 = interpreter_pop(interp);
        CH_Address v2 = interpreter_pop(interp);
        CH_Address v3 = interpreter_pop(interp);
        interpreter_push(interp, v1);
        interpreter_push(interp, v3);
        interpreter_push(interp, v2);
        break;
      }
      
      case DW_OP_deref: {
        CH_Address v = interpreter_pop(interp);
        CH_Address mem = read_address_from_memory(interp, v, interp->addr_size);
        interpreter_push(interp, mem);
        break;
      }
      case DW_OP_deref_size: {
        uint8_t c = 0;
        interp->is_OK = read_uint8_t(interp->obj, &expr, expr_end, &c);
        if (interp->is_OK) {
          CH_Address v = interpreter_pop(interp);
          CH_Address mem = read_address_from_memory(interp, v, c);
          interpreter_push(interp, mem);
        }
        break;
      }
      case DW_OP_xderef: {
        CH_Address v = interpreter_pop(interp);
        interpreter_pop(interp); /* unused address space identifier */
        CH_Address mem = read_address_from_memory(interp, v, interp->addr_size);
        interpreter_push(interp, mem);
        break;
      }
      case DW_OP_xderef_size: {
        uint8_t c = 0;
        interp->is_OK = read_uint8_t(interp->obj, &expr, expr_end, &c);
        if (interp->is_OK) {
          CH_Address v = interpreter_pop(interp);
          interpreter_pop(interp); /* unused address space identifier */
          CH_Address mem = read_address_from_memory(interp, v, c);
          interpreter_push(interp, mem);
        }
        break;
      }
      
      /* XXX not yet implemented, but probably should be */
      case DW_OP_call_ref:
      case DW_OP_form_tls_address:
      case DW_OP_call_frame_cfa: {
        dwarf2_invalid_warning(interp->obj,
                               "Unimplemented Dwarf2 expression operator %d", op);
        interp->is_OK = 0;
        break;
      }
      
      case DW_OP_push_object_address: {
        if (!interp->has_object_base_address) {
          dwarf2_invalid_warning(interp->obj,
                                 "DW_OP_push_object_address in non-data-location context");
          interp->is_OK = 0;
        } else {
          interpreter_push(interp, interp->object_base_address);
        }
        break;
      }
      
      case DW_OP_abs: DWARF2_UNARY_OP( (CH_Address)llabs(v) )
      case DW_OP_not: DWARF2_UNARY_OP( ~v )
      case DW_OP_neg: DWARF2_UNARY_OP( -v )
      
      case DW_OP_and: DWARF2_BINARY_OP( v1 & v2 )
      case DW_OP_minus: DWARF2_BINARY_OP( v2 - v1 )
      case DW_OP_mul: DWARF2_BINARY_OP( v1*v2 )
      case DW_OP_or: DWARF2_BINARY_OP( v1 | v2 )
      case DW_OP_plus: DWARF2_BINARY_OP( v1 + v2 )
      case DW_OP_shl: DWARF2_BINARY_OP( v2 << v1  )
      case DW_OP_shr: DWARF2_BINARY_OP( (CH_Address)v2 >> v1 )
      case DW_OP_shra: DWARF2_BINARY_OP( v2 >> v1 )
      case DW_OP_xor: DWARF2_BINARY_OP( v1 ^ v2 )

      case DW_OP_div: {
        CH_SignedAddress v1 = interpreter_pop(interp);
        CH_SignedAddress v2 = interpreter_pop(interp);
        if (v1 == 0) {
          interp->is_program_state_error = 1;
          interpreter_push(interp, 0);
        } else {
          interpreter_push(interp, v2/v1);
        }
        break;
      }
      case DW_OP_mod: {
        CH_SignedAddress v1 = interpreter_pop(interp);
        CH_SignedAddress v2 = interpreter_pop(interp);
        if (v1 == 0) {
          interp->is_program_state_error = 1;
          interpreter_push(interp, 0);
        } else {
          interpreter_push(interp, v2%v1);
        }
        break;
      }
      case DW_OP_plus_uconst: {
        CH_Address v1 = interpreter_pop(interp);
        uint64_t c = 0;
        interp->is_OK = read_uLEB128(interp->obj, &expr, expr_end, &c);
        interpreter_push(interp, v1 + c);
        break;
      }

      case DW_OP_le: DWARF2_BINARY_OP( v2 <= v1 )
      case DW_OP_ge: DWARF2_BINARY_OP( v2 >= v1 )
      case DW_OP_eq: DWARF2_BINARY_OP( v2 == v1 )
      case DW_OP_lt: DWARF2_BINARY_OP( v2 < v1 )
      case DW_OP_gt: DWARF2_BINARY_OP( v2 > v1 )
      case DW_OP_ne: DWARF2_BINARY_OP( v2 != v1 )
      
      case DW_OP_nop:
        break;
      case DW_OP_skip: {
        uint16_t c = 0;
        interp->is_OK = read_uint16_t(interp->obj, &expr, expr_end, &c);
        expr += (int16_t)c;
        break;
      }
      case DW_OP_bra: {
        uint16_t c = 0;
        CH_Address v = interpreter_pop(interp);
        interp->is_OK = read_uint16_t(interp->obj, &expr, expr_end, &c);
        if (v) {
          expr += (int16_t)c;
        }
        break;
      }
      case DW_OP_call2: {
        uint16_t w;
        interp->is_OK = read_uint16_t(interp->obj, &expr, expr_end, &w);
        interp_do_call(interp, interp->cu_reader->cu_offset + w);
        break;
      }
      case DW_OP_call4: {
        uint32_t w;
        interp->is_OK = read_uint32_t(interp->obj, &expr, expr_end, &w);
        interp_do_call(interp, interp->cu_reader->cu_offset + w);
        break;
      }
      
      case DW_OP_regx: {
        uint64_t c = 0;        
        interp->is_OK = read_uLEB128(interp->obj, &expr, expr_end, &c);
        interp->stacked_register = c;
        break;
      }
      
      case DW_OP_piece: {
        uint64_t bytes = 0;        
        interp->is_OK = read_uLEB128(interp->obj, &expr, expr_end, &bytes);
        interp_make_piece(interp, 0, bytes*8);
        break;
      }
     
      case DW_OP_bit_piece: {
        uint64_t bits = 0;
        interp->is_OK = read_uLEB128(interp->obj, &expr, expr_end, &bits);
        if (interp->is_OK) {
          uint64_t offset_bits = 0;
          interp->is_OK = read_uLEB128(interp->obj, &expr, expr_end, &offset_bits);
          interp_make_piece(interp, offset_bits, bits);
        }
        break;
      }
     
      default:
        if (DW_OP_lit0 <= op && op <= DW_OP_lit31) {
          interpreter_push(interp, op - DW_OP_lit0);
        } else if (DW_OP_reg0 <= op && op <= DW_OP_reg31) {
          interp->stacked_register = op - DW_OP_reg0;
        } else if (DW_OP_breg0 <= op && op <= DW_OP_breg31) {
          int64_t c = 0;
          interp->is_OK = read_LEB128(interp->obj, &expr, expr_end, &c);
          if (interp->is_OK) {
            CH_Address addr = read_address_from_dwarf2_reg(interp, op - DW_OP_breg0);
            interpreter_push(interp, addr + c);
          }
        } else {
          dwarf2_invalid_warning(interp->obj,
                                 "Unknown Dwarf2 expression operator %d", op);
          interp->is_OK = 0;
        }
    }
  
    if (op != DW_OP_piece && op != DW_OP_bit_piece) {
      interp->operation_count++;
    }
  }
  
  if (!interp->is_OK)
    return;
    
  if (interp->piece_count > 0) {
    /* We saw a OP_*piece operator; there should be nothing on the stack */
    if (interp->stacked_register >= 0 || interp->stack_count > 0) {
      dwarf2_invalid_warning(interp->obj,
                             "Dwarf2 expression has operators after final *piece op");
      interp->is_OK = 0;
    }
  }
}

static void intersect_range64(CH_Range64* dest, CH_Range64* source) {
  uint64_t start = dest->start;
  uint64_t end = start + dest->length;
  uint64_t s_start = source->start;
  uint64_t s_end = s_start + source->length;
  if (s_start > start) {
    start = s_start;
  }
  if (s_end < end) {
    end = s_end;
  }
  if (start < end) {
    dest->start = start;
    dest->length = end - start;
  } else {
    dest->length = 0;
  }
}

static void interpreter_intersect_validity_ranges(Dwarf2ExprInterpreter* interp,
    CH_Range64* basic_expression_validity) {
  int i, j;
  CH_GrowBuf buf;
  int count = 0;

  if (!basic_expression_validity)
    return;
  if (!interp->validity_range) {
    interp->validity_range = basic_expression_validity;
    return;
  }
  
  init_buf(&buf);
  for (i = 0; interp->validity_range[i].length; ++i) {
    for (j = 0; basic_expression_validity[j].length; ++j) {
      CH_Range64 d = interp->validity_range[i];
      intersect_range64(&d, &basic_expression_validity[j]);
      if (d.length) {
        ensure_buffer_size(&buf, (count + 1)*sizeof(CH_Range64));
        ((CH_Range64*)buf.data)[count] = d;
        ++count;
      }
    }
  }
  
  safe_free(interp->validity_range);
  safe_free(basic_expression_validity);
  interp->validity_range = safe_realloc(buf.data, count*sizeof(CH_Range64));
}

static CH_DbgValuePiece* interpret_location_list(Dwarf2ExprInterpreter* interp,
  EntryReader* reader, CH_Dwarf2_DW_AT attribute, int take_pieces) {
  uint8_t* data;
  uintptr_t size;
  CH_Range64* basic_expression_validity;
  CH_DbgValuePiece* result;

  if (!find_location_expression(reader, attribute, interp->pc_addr, &data, &size,
                                &basic_expression_validity)) {
    interp->is_OK = 0;
    return NULL;
  }

  interpreter_intersect_validity_ranges(interp, basic_expression_validity);

  if (!data || !size) {
    /* it's completely undefined */
    CH_DbgValuePiece pieces[2] = { { CH_PIECE_UNDEFINED, 0, 0, 0 },
                                   { CH_PIECE_END, 0, 0, 0 } };

    if (!take_pieces)
      return NULL;

    result = malloc(sizeof(pieces));
    memcpy(result, pieces, sizeof(pieces));
    return result;
  }

  interpreter_run(interp, data, size);
  if (!interp->is_OK || !take_pieces)
    return NULL;
    
  if (interp->piece_count == 0) {
    /* finished evaluating simple expression */
    /* Unknown size here. Treat this as "the rest". */
    interp_make_piece(interp, 0, 0);
    if (!interp->is_OK)
      return NULL;
  } 

  result = safe_realloc(interp->pieces.data,
                        (interp->piece_count + 1)*sizeof(CH_DbgValuePiece));
  result[interp->piece_count].type = CH_PIECE_END;
  interp->pieces.data = NULL;
 
  return result;
}

CH_DbgValuePiece* dwarf2_examine_value(QueryThread* q, CH_DbgDwarf2Object* obj,
                                       CH_DbgDwarf2Offset function_offset,
                                       CH_Address pc_addr,
                                       CH_DbgDwarf2Offset variable_offset,
                                       CH_DbgProgramState* state,
                                       CH_Range** valid_instruction_ranges) {
  uint64_t dwarf_pc_addr;
  CH_DbgDwarf2Offset info_cu_offset =
    find_compilation_unit_offset_for(obj, function_offset);
  CompilationUnitReader cu_reader;
  EntryReader function_reader;
  EntryReader variable_reader;
  CH_DbgValuePiece* result;
  Dwarf2ExprInterpreter interp;

  if (!translate_file_offset_to_dwarf_address(obj, pc_addr, &dwarf_pc_addr))
    return NULL;

  if (!read_debug_info_header(obj, info_cu_offset, &cu_reader))
    return NULL;
  
  if (function_offset) {
    if (!begin_reading_entry(&cu_reader, function_offset, &function_reader))
      return NULL;
    if (function_reader.is_empty)
      return NULL;
  }
  
  if (!begin_reading_entry(&cu_reader, variable_offset, &variable_reader))
    return NULL;
  if (variable_reader.is_empty)
    return NULL;
      
  interpreter_init(&interp, &cu_reader, function_offset ? &function_reader : NULL,
                   state, NULL, dwarf_pc_addr);
      
  result = interpret_location_list(&interp, &variable_reader, DW_AT_location, 1);
  if (!result) {
    interpreter_destroy(&interp);
    return NULL;
  }

  if (!interp.validity_range) {
    *valid_instruction_ranges = NULL;
  } else {
    int i;
    CH_Range* ranges;
    
    for (i = 0; interp.validity_range[i].length; ++i) {
    }
    ranges = safe_malloc(sizeof(CH_Range)*(i + 1));
    for (i = 0; interp.validity_range[i].length; ++i) {
      translate_dwarf_address_to_file_offset(obj, interp.validity_range[i].start,
                                             &ranges[i].start);
      ranges[i].length = interp.validity_range[i].length;
    }
    ranges[i].start = ranges[i].length = 0;
    *valid_instruction_ranges = ranges;
  }
  
  interpreter_destroy(&interp);
  
  return result;
}

static int64_t find_type_size(CompilationUnitReader* cu_reader,
                              CH_DbgDwarf2Offset type_offset) {
  EntryReader reader;
  int found;
  CH_DbgDwarf2Offset ref;
  uint64_t size;

  if (!begin_reading_entry(cu_reader, type_offset, &reader))
    return -1;
  if (reader.is_empty)
    return 1;

  if (!read_attribute_unsigned_constant(&reader, DW_AT_byte_size, &size, &found))
    return -1;
  if (found)
    return size;
  
  if (!read_attribute_reference(&reader, DW_AT_specification, &ref, &found))
    return -1;
  if (found)
    return find_type_size(cu_reader, ref);

  return -1;
}

static int compute_data_location(EntryReader* reader, uint64_t base_address,
    CH_DbgProgramState* state, CH_Address dwarf_pc_addr, uint64_t* result,
    int* is_dynamic, int* is_state_error) {
  uint8_t* data;
  CH_Dwarf2_DW_FORM form;
  if (!find_attribute(reader, DW_AT_data_member_location, &data, &form))
    return 0;

  *is_dynamic = 0;
  *is_state_error = 0;
   
  /* "data" forms represent constant offsets, so only "block" location
   * forms indicate a dynamic offset */
  switch (form) {
    case DW_FORM_block1:
    case DW_FORM_block2:
    case DW_FORM_block4:
    case DW_FORM_block: {
      Dwarf2ExprInterpreter interp;
      CH_DbgValuePiece* pieces;

      interpreter_init(&interp, reader->cu_reader, NULL, state, NULL,
                       dwarf_pc_addr);
      interp.has_object_base_address = 1;
      interp.object_base_address = 0;
      interpreter_push(&interp, base_address);

      pieces = interpret_location_list(&interp, reader, DW_AT_data_member_location, 1);
      interpreter_destroy(&interp);
      if (!pieces)
        return 0;
      
      switch (pieces[0].type) {
        case CH_PIECE_MEMORY:
          *result = pieces[0].source;
          break;
        case CH_PIECE_REGISTER:
          *result = read_address_from_reg(&interp, (uint32_t)pieces[0].source);
          if (!interp.is_program_state_error)
            break;
          /* else fall through */
        case CH_PIECE_ERROR:
          if (state) {
            *is_state_error = 1;
            safe_free(pieces);
            return 0;
          }
          *is_dynamic = 1;
          break;
        default:
          safe_free(pieces);
          return 0;
      }
      safe_free(pieces);
      return 1;
    }
    
    default: {
      int64_t offset;
      int found;
      if (!read_attribute_signed_constant(reader, DW_AT_data_member_location, &offset, &found))
        return 0;
      if (!found) {
        /* probably a member of a union */
        *result = 0;
      } else {
        *result = base_address + offset;
      }
      return 1;
    }
  }
}

static int scan_struct_fields(EntryReader* reader, CH_DbgDwarf2TypeInfo* info) {
  if (!reader->has_children)
    return 1;
    
  /* descend into this entry */
  CH_DbgDwarf2Offset child = find_end_of_entry(reader);
  for (;;) {
    EntryReader child_reader;
    if (!begin_reading_entry(reader->cu_reader, child, &child_reader))
      return 0;
    if (child_reader.is_empty)
      return 1;
      
    switch (child_reader.tag) {
      case DW_TAG_inheritance:
      case DW_TAG_member: {
        uint64_t offset;
        int is_dynamic;
        int is_state_error;
        if (!compute_data_location(&child_reader, 0, NULL, 0, &offset,
                                   &is_dynamic, &is_state_error))
          return 0;
        info->is_dynamic = is_dynamic;
        break;
      }
        
      default:
        break;
    }

    child = find_end_of_entry_subtree(&child_reader);
  }
}

static int fill_in_type_info(CompilationUnitReader* cu_reader,
                             CH_DbgDwarf2Offset type_offset,
                             CH_DbgDwarf2TypeInfo* info) {
  EntryReader reader;
  int found;
  CH_DbgDwarf2Offset ref;
  uint64_t size;
  CH_DbgDwarf2Object* obj = cu_reader->obj;

  if (!begin_reading_entry(cu_reader, type_offset, &reader))
    return 0;
  if (reader.is_empty)
    return 0; /* not a real type */

  if (!read_attribute_reference(&reader, DW_AT_specification, &ref, &found))
    return 0;
  if (found) {
    if (!fill_in_type_info(cu_reader, ref, info))
      return 0;
  }
  
  if (!read_attribute_string(&reader, DW_AT_name, &info->name, &found))
    return 0;

  if (!read_attribute_unsigned_constant(&reader, DW_AT_byte_size, &size, &found))
    return 0;
  if (found) {
    info->bytes_size = (int64_t)size;
  }
  
  if (!read_attribute_flag(&reader, DW_AT_declaration, &found))
    return 0;
  if (found) {
    info->is_declaration_only = 1;
  }

  if (!read_attribute_reference(&reader, DW_AT_type, &info->inner_type_offset, &found))
    return 0;

  switch (reader.tag) {
    case DW_TAG_base_type: {
      uint64_t encoding;
      if (!read_attribute_unsigned_constant(&reader, DW_AT_encoding, &encoding, &found))
        return 0;
      if (!found) {
        dwarf2_invalid_warning(obj,
                               "Missing base type encoding attribute");
        return 0;
      }
      switch (encoding) {
        case DW_ATE_boolean:
        case DW_ATE_signed:
        case DW_ATE_signed_char:
        case DW_ATE_unsigned:
        case DW_ATE_unsigned_char:
          info->kind = CH_TYPE_INT;
          info->int_is_signed =
            encoding == DW_ATE_signed || encoding == DW_ATE_signed_char;
          break;
        
        case DW_ATE_float:
          info->kind = CH_TYPE_FLOAT;
          break;
          
        default:
          dwarf2_invalid_warning(obj,
                                 "Unsupported base type encoding attribute");
          return 0;
      }
      break;
    }
    
    case DW_TAG_array_type:
      info->kind = CH_TYPE_ARRAY;
      /* XXX support DW_TAG_bit_stride? */
      /* XXX support multidimensional arrays? */
      if (info->bytes_size > 0 && info->inner_type_offset) {
        int64_t elem_size = find_type_size(cu_reader, info->inner_type_offset);
        if (elem_size > 0) {
          info->array_length = info->bytes_size/elem_size;
        }
      }
      break;
   
    case DW_TAG_enumeration_type:
      info->kind = CH_TYPE_ENUM;
      break;
    
    case DW_TAG_subroutine_type:
      info->kind = CH_TYPE_FUNCTION;
      break;
    
    case DW_TAG_structure_type:
    case DW_TAG_union_type:
    case DW_TAG_class_type:
      info->kind = CH_TYPE_STRUCT;
      if (reader.tag == DW_TAG_structure_type) {
        info->struct_kind = CH_STRUCT_KIND_STRUCT;
      } else if (reader.tag == DW_TAG_union_type) {
        info->struct_kind = CH_STRUCT_KIND_UNION;
      } else {
        info->struct_kind = CH_STRUCT_KIND_CLASS;
      }
      /* compute is_dynamic */
      scan_struct_fields(&reader, info);
      break;

    case DW_TAG_typedef:
      info->kind = CH_TYPE_TYPEDEF;
      break;

    case DW_TAG_pointer_type:
      info->kind = CH_TYPE_POINTER;
      info->pointer_is_reference = 0;
      break;
      
    case DW_TAG_reference_type:
      info->kind = CH_TYPE_POINTER;
      info->pointer_is_reference = 1;
      break;
      
    case DW_TAG_const_type:
      info->kind = CH_TYPE_ANNOTATION;
      info->annotation_kind = CH_ANNOTATION_CONST;
      break;
    
    case DW_TAG_volatile_type:
      info->kind = CH_TYPE_ANNOTATION;
      info->annotation_kind = CH_ANNOTATION_VOLATILE;
      break;
    
    case DW_TAG_restrict_type:
      info->kind = CH_TYPE_ANNOTATION;
      info->annotation_kind = CH_ANNOTATION_RESTRICT;
      break;
    
    default:
      dwarf2_invalid_warning(obj, "Unknown type tag %d\n", reader.tag);
      break;
  }
  
  return 1;
}

int dwarf2_lookup_type_info(QueryThread* q, CH_DbgDwarf2Object* obj,
                            CH_DbgDwarf2Offset type_offset,
                            CH_DbgDwarf2TypeInfo* info) {
  CH_DbgDwarf2Offset info_cu_offset =
    find_compilation_unit_offset_for(obj, type_offset);
  CompilationUnitReader cu_reader;
  CH_StringBuf container_prefix;
  CH_StringBuf namespace_prefix;

  if (!read_debug_info_header(obj, info_cu_offset, &cu_reader))
    return 0;

  if (!lookup_compilation_unit_info(&cu_reader, &info->cu))
    return 0;
    
  info->kind = CH_TYPE_UNKNOWN;
  info->is_dynamic = 0;
  info->is_declaration_only = 0;
  info->inner_type_offset = 0;
  info->name = NULL;
  info->container_prefix = NULL;
  info->namespace_prefix = NULL;  
  info->bytes_size = -1;

  if (!fill_in_type_info(&cu_reader, type_offset, info))
    return 0;
  
  stringbuf_init(&container_prefix);
  stringbuf_init(&namespace_prefix);
  /* extract_prefixes chases DW_AT_specification links for us */
  if (!extract_prefixes(&cu_reader, &namespace_prefix, &container_prefix,
                        type_offset)) {
    stringbuf_destroy(&namespace_prefix);
    stringbuf_destroy(&container_prefix);
    return 0;
  }
  
  if (stringbuf_len(&container_prefix)) {
    info->container_prefix = stringbuf_finish(&container_prefix);
  }
  if (stringbuf_len(&namespace_prefix)) {
    info->namespace_prefix = stringbuf_finish(&namespace_prefix);
  }
  
  return 1;
}

typedef int (* ScanChildEntriesCallback)
  (EntryReader* child_reader, void* closure);

static int iterate_type_child_entries_recursive(CompilationUnitReader* cu_reader,
    CH_DbgDwarf2Offset type_offset, ScanChildEntriesCallback callback,
    void* closure) {
  EntryReader reader;
  int found;
  CH_DbgDwarf2Offset ref;

  if (!begin_reading_entry(cu_reader, type_offset, &reader))
    return 0;
  if (reader.is_empty)
    return 0; /* not a real type */
  
  if (!read_attribute_reference(&reader, DW_AT_specification, &ref, &found))
    return 0;
  if (found) {
    if (!iterate_type_child_entries_recursive(cu_reader, ref, callback, closure))
      return 0;
  }
    
  if (reader.has_children) {
    CH_DbgDwarf2Offset child = find_end_of_entry(&reader);
    for (;;) {
      EntryReader child_reader;
      if (!begin_reading_entry(cu_reader, child, &child_reader))
        return 0;
      if (child_reader.is_empty)
        break;
      if (!callback(&child_reader, closure))
        return 0;
      child = find_end_of_entry_subtree(&child_reader);
    }
  }
  
  return 1;
}
  
static int iterate_type_child_entries(CH_DbgDwarf2Object* obj,
    CH_DbgDwarf2Offset type_offset, ScanChildEntriesCallback callback,
    void* closure) {
  CH_DbgDwarf2Offset info_cu_offset =
    find_compilation_unit_offset_for(obj, type_offset);
  CompilationUnitReader cu_reader;
    
  if (!read_debug_info_header(obj, info_cu_offset, &cu_reader))
    return 0;
  return iterate_type_child_entries_recursive(&cu_reader, type_offset, callback, closure);
}

typedef struct {
  CH_DbgDwarf2EnumValueIterator iterator;
  void*                         inner_closure;
} EnumValueIteratorClosure;

static int iterate_type_enum_values_callback(EntryReader* reader, void* closure) {
  EnumValueIteratorClosure* cl = closure;
  char const* name = NULL;
  int64_t value;
  int found;
  
  if (reader->tag != DW_TAG_enumerator)
    return 1;

  if (!read_attribute_signed_constant(reader, DW_AT_const_value, &value, &found))
    return 0;
  if (!found) {
    dwarf2_invalid_warning(reader->cu_reader->obj, "enum member has no value!");
    return 0;
  }

  if (!read_attribute_string(reader, DW_AT_name, &name, &found))
    return 0;
    
  cl->iterator(cl->inner_closure, name, value);
  return 1;
}

int dwarf2_iterate_type_enum_values(QueryThread* q,
    CH_DbgDwarf2Object* obj, CH_DbgDwarf2Offset type_offset,
    CH_DbgDwarf2EnumValueIterator iterator, void* closure) {
  EnumValueIteratorClosure cl = { iterator, closure };
  return iterate_type_child_entries(obj, type_offset,
                                    iterate_type_enum_values_callback, &cl);
}

typedef struct {
  CH_DbgDwarf2FunctionParameterIterator iterator;
  void*                                 inner_closure;
} FunctionParameterIteratorClosure;

static int iterate_type_function_parameter_callback(EntryReader* reader, void* closure) {
  FunctionParameterIteratorClosure* cl = closure;
  char const* name = NULL;
  CH_DbgDwarf2Offset type_offset = 0;
  int found;
  
  if (reader->tag != DW_TAG_formal_parameter)
    return 1;

  if (!read_attribute_reference(reader, DW_AT_type, &type_offset, &found))
    return 0;

  if (!read_attribute_string(reader, DW_AT_name, &name, &found))
    return 0;
    
  cl->iterator(cl->inner_closure, name, type_offset);
  return 1;
}

int dwarf2_iterate_type_function_parameters(QueryThread* q,
    CH_DbgDwarf2Object* obj, CH_DbgDwarf2Offset type_offset,
    CH_DbgDwarf2FunctionParameterIterator iterator, void* closure) {
  FunctionParameterIteratorClosure cl = { iterator, closure };
  return iterate_type_child_entries(obj, type_offset,
                                    iterate_type_function_parameter_callback, &cl);
}

typedef struct {
  CH_DbgDwarf2StructFieldIterator iterator;
  void*                           inner_closure;
} StructFieldIteratorClosure;

static int iterate_type_struct_field_callback(EntryReader* reader, void* closure) {
  StructFieldIteratorClosure* cl = closure;
  char const* name = NULL;
  int found;
  int64_t byte_offset;
  CH_DbgDwarf2Offset type_offset;
  uint8_t is_subobject = reader->tag == DW_TAG_inheritance;
  int32_t byte_size = -1;
  int32_t bit_size = -1;
  int32_t bit_offset = -1;
  uint64_t raw_constant;
  int is_dynamic;
  int is_state_error;
  int is_synthetic;

  if (reader->tag != DW_TAG_member && reader->tag != DW_TAG_inheritance)
    return 1;

  if (!compute_data_location(reader, 0, NULL, 0, &raw_constant,
                             &is_dynamic, &is_state_error))
    return 0;
  if (is_dynamic)
    return 1;
  byte_offset = raw_constant;

  if (!read_attribute_reference(reader, DW_AT_type, &type_offset, &found))
    return 0;
  if (!found) {
    dwarf2_invalid_warning(reader->cu_reader->obj, "Struct field has no type");
    return 0;
  }
  
  if (!read_attribute_string(reader, DW_AT_name, &name, &found))
    return 0;
  if (!read_attribute_flag(reader, DW_AT_artificial, &is_synthetic))
    return 0;
    
  if (!read_attribute_unsigned_constant(reader, DW_AT_bit_offset, &raw_constant, &found))
    return 0;
  if (found) {
    uint64_t raw_byte_size;
    if (!read_attribute_unsigned_constant(reader, DW_AT_byte_size, &raw_byte_size, &found))
      return 0;
    if (!found) {
      dwarf2_invalid_warning(reader->cu_reader->obj, "No byte size for bitfield");
    } else {
      uint64_t raw_bit_size;
      if (!read_attribute_unsigned_constant(reader, DW_AT_bit_size, &raw_bit_size, &found))
        return 0;
      if (!found) {
        dwarf2_invalid_warning(reader->cu_reader->obj, "No bit size for bitfield");
      } else if ((int32_t)raw_constant != raw_constant) {
        dwarf2_invalid_warning(reader->cu_reader->obj, "Bit offset %ulld is out of range",
                               (unsigned long long)raw_constant);
      } else if ((int32_t)raw_byte_size != raw_byte_size) {
        dwarf2_invalid_warning(reader->cu_reader->obj, "Byte size %ulld is out of range",
                               (unsigned long long)raw_byte_size);
      } else if ((int32_t)raw_bit_size != raw_bit_size) {
        dwarf2_invalid_warning(reader->cu_reader->obj, "Byte size %ulld is out of range",
                               (unsigned long long)raw_byte_size);
      } else {
        bit_offset = (int32_t)raw_constant;
        byte_size = (int32_t)raw_byte_size;
        bit_size = (int32_t)raw_bit_size;
      }
    }
  }
    
  cl->iterator(cl->inner_closure, name, byte_offset, type_offset, is_subobject,
               is_synthetic, byte_size, bit_size, bit_offset);
  return 1;
}

int dwarf2_iterate_type_struct_fields(QueryThread* q,
    CH_DbgDwarf2Object* obj, CH_DbgDwarf2Offset type_offset,
    CH_DbgDwarf2StructFieldIterator iterator, void* closure) {
  StructFieldIteratorClosure cl = { iterator, closure };
  return iterate_type_child_entries(obj, type_offset,
                                    iterate_type_struct_field_callback, &cl);
}
