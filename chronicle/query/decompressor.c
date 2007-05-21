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

#include "decompressor.h"
#include "compressor.h"
#include "config.h"
#include "util.h"

#include <memory.h>

void decompress_global_init() {
}

void* decompress_all(uint8_t* data, int size, uint8_t type, uint32_t* len) {
  z_stream zstream;
  int status;
  CH_GrowBuf buf;
  int decompressed_len = 0;

  if (type == CH_COMPRESSTYPE_NONE) {
    void* result = safe_malloc(size);
    memcpy(result, data, size);
    *len = size;
    return result;
  }

  zstream.zalloc = NULL;
  zstream.zfree = NULL;
  zstream.opaque = NULL;
  zstream.next_in = data;
  zstream.avail_in = size;
  if (inflateInit2(&zstream, WINDOW_BITS) != Z_OK) {
    fatal_error(77, "Stream init failed!");
  }

  init_buf(&buf);
  ensure_buffer_size(&buf, 65536);

  for (;;) {
    zstream.next_out = buf.data + decompressed_len;
    zstream.avail_out = buf.size - decompressed_len;
    status = inflate(&zstream, Z_NO_FLUSH);
    decompressed_len = zstream.next_out - buf.data;
    if (status == Z_STREAM_END) {
      inflateEnd(&zstream);
      *len = decompressed_len;
      return safe_realloc(buf.data, decompressed_len);
    } else if (status != Z_OK) {
      fatal_error(77, "Error decompressing stream");
    }
    ensure_buffer_size(&buf, decompressed_len*2);
  }
}

uint16_t* decompress_skip_bit_run_block(uint16_t* ptr, int count) {
  while (count > 0) {
    count -= *ptr;
    ptr++;
  }
  if (count != 0) {
    fatal_error(78, "Misaligned block");
  }
  return ptr;
}

int decompress_check_any_set_in_bit_run_block(uint16_t* p,
    CH_DecompressorBitRunRange* ranges, int num_ranges) {
  int offset = 0;
  int bit = 0;
  if (num_ranges <= 0)
    return 0;
    
  for (;;) {
    /* invariant: offset <= ranges->offset */

    while (offset + *p <= ranges->offset || !*p) {
      offset += *p;
      p++;
      bit ^= 1;
    }
    /* now offset <= ranges->offset and offset + *p > ranges->offset */
    if (bit) {
      /* this run of ones includes the first position in the range */
      return 1;
    }

    /* exit the run of zeroes. */
    offset += *p;
    p++;
    bit = 1;
    
    /* Skip all ranges that fell entirely inside this run.
       Note that range offsets only increase as we go through the array,
       so old_offset <= ranges->offset always holds. */
    while (ranges->offset + ranges->length <= offset) {
      ranges++;
      num_ranges--;
      if (num_ranges <= 0)
        return 0;
    }
    
    if (offset >= ranges->offset) {
      /* from above we have ranges->offset + ranges->length > offset, so
         this run of ones intersects the range */
      return 1;
    }
  }
}
