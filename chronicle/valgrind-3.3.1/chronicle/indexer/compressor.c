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

#include "compressor.h"
#include "util.h"

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define PTR_BITS (sizeof(void*)*8)

static void compressor_none(CH_CompressorState* state, void* bytes, int len) {
  ensure_buffer_size(&state->output, state->output_len + len);
  memcpy(state->output.data + state->output_len, bytes, len);
  state->output_len += len;
}

#define ZLIB_COMPRESSION_LEVEL 1
static void zlib_deflate_all(CH_CompressorState* state, int flush) {
  do {
    int status;
    /* ensure there's plenty of room in the buffer */
    ensure_buffer_size(&state->output, state->output_len + 20000);
    state->zstream.next_out = state->output.data + state->output_len;
    state->zstream.avail_out = state->output.size - state->output_len;
    status = deflate(&state->zstream, flush);
    state->output_len = state->zstream.next_out - state->output.data;

    if (status != Z_OK && status != Z_STREAM_END && status != Z_BUF_ERROR) {
      fprintf(stderr, "zlib error in compression\n");
      exit(77);
    }
    /* if zlib filled the output buffer, then go around again */
  } while (state->zstream.avail_out == 0);
}

void compress_data(CH_CompressorState* state, void* bytes, int len) {
  if (state->type == CH_COMPRESSTYPE_NONE) {
    compressor_none(state, bytes, len);
    return;
  }

  state->zstream.next_in = bytes;
  state->zstream.avail_in = len;
  zlib_deflate_all(state, Z_NO_FLUSH);
}

void compress_global_init() {
}

void compress_init(CH_CompressorState* state, uint8_t type) {
  state->output.data = NULL;
  state->output.size = 0;
  state->output_len = 0;
  state->type = type;

  if (state->type == CH_COMPRESSTYPE_NONE)
    return;

  state->zstream.zalloc = NULL;
  state->zstream.zfree = NULL;
  state->zstream.opaque = NULL;
  if (deflateInit2(&state->zstream, ZLIB_COMPRESSION_LEVEL, Z_DEFLATED,
                   WINDOW_BITS, 9, Z_DEFAULT_STRATEGY) != Z_OK) {
    fatal_error(77, "zlib error at init\n");
  }
}

static void write_corpus(CH_CompressorState* state, const char* ID) {
#ifdef CH_COMPRESSOR_BUILD_CORPUS
  char template[1024];
  int fd;

  sprintf(template, "corpus.%s.%s.XXXXXX", ID,
          state->type == CH_COMPRESSTYPE_NONE ? "raw" : "cmpr");
  fd = mkstemp(template);
  if (fd < 0) {
    fatal_perror(99, "Cannnot create temp file %s\n", template);
  }

  if (write(fd, state->output.data, state->output_len) != state->output_len) {
    fatal_perror(100, "Cannnot write to temp file %s\n", template);
  }
  
  if (close(fd) < 0) {
    fatal_perror(101, "Cannnot close temp file %s\n", template);
  }
#endif
}

void compress_done(CH_CompressorState* state) {
  if (state->type == CH_COMPRESSTYPE_NONE)
    return;

  zlib_deflate_all(state, Z_FINISH);
  if (deflateEnd(&state->zstream) != Z_OK) {
    fatal_error(77, "zlib error at end!\n");
  }
}

void compress_finish(CH_CompressorState* state, const char* ID) {
  compress_finish_nofree(state, ID);
  free(state->output.data);
}

void compress_finish_nofree(CH_CompressorState* state, const char* ID) {
  if (ID) {
    write_corpus(state, ID);
  }
#ifdef CH_COMPRESSOR_METRICS
  fprintf(stderr, "%s ITERATIONS %d COLLISIONS: %d\n", ID,
          lz_iterations, lz_collisions);
#endif
}

void compress_bit_runs(CH_CompressorState* state, uintptr_t* data, int count) {
  int word_offset = 0;
  int bit_offset = 0;

  /* We generate a sequence of 16-bit values: number of zero bits,
     number of one bits, etc. Zero-length zero bit runs are allowed. */
  uintptr_t mask = 0;
  for (;;) {
    /* Find number of consecutive same-bits */
    uintptr_t v = data[word_offset];
    if ((v >> bit_offset) == (mask >> bit_offset)) {
      uint32_t bits = (uint32_t)(PTR_BITS - bit_offset);
      uint16_t bits_out;
      ++word_offset;
      while (word_offset < count && data[word_offset] == mask) {
        bits += PTR_BITS;
        ++word_offset;
      }
      if (word_offset < count) {
        bit_offset = ffsl(data[word_offset]^mask) - 1;
        bits += (uint16_t)bit_offset;
      }

      while (bits >= 0x10000) {
        /* won't fit in 16 bits. Emit it in multiple parts */
        static uint16_t data[] = { 0xFFFF, 0 };
        bits -= data[0];
        compress_data(state, data, sizeof(data));
      }
      bits_out = (uint16_t)bits;
      compress_data(state, &bits_out, 2);

      if (word_offset >= count)
        return;
    } else {
      uint16_t bits = (uint16_t)(ffsl((v^mask) >> bit_offset) - 1);
      bit_offset += bits;

      compress_data(state, &bits, 2);
    }

    mask = ~mask;
  }
}
