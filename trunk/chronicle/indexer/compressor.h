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

#ifndef COMPRESSOR_H__
#define COMPRESSOR_H__

/**
 * Compression functions. For compressing basic binary data these are just
 * wrappers around zlib. We also have functions for run-length encoding
 * bitmaps.
 */

#include "config.h"
#include "util.h"

#include <stdint.h>

#include <zlib.h>
#define WINDOW_BITS (-MAX_WBITS)
  
#define CH_COMPRESSTYPE_NONE    0
#define CH_COMPRESSTYPE_BITRUNS 1
#define CH_COMPRESSTYPE_DATA    2

typedef struct _CT_CompressorState {
  CH_GrowBuf output;
  uint32_t   output_len;
  uint8_t    type;
  z_stream   zstream;
} CH_CompressorState;

void compress_global_init();
/** Initialize a compressor for compressing data of the given type. */
void compress_init(CH_CompressorState* state, uint8_t type);
/** Feed some data into the compressor. */
void compress_data(CH_CompressorState* state, void* bytes, int len);
/**
 * We're done compressing data. The output can be gathered from 'output' now.
 */
void compress_done(CH_CompressorState* state);
/**
 * Clean up this compressor. The ID is used to report metrics and to
 * help name corpus files.
 */
void compress_finish(CH_CompressorState* state, const char* ID);
/**
 * Reset this compressor --- clean up but leave it in the initialized state
 * so it can be used again. The ID is used to report metrics and to help name
 * corpus files.
 */
void compress_finish_nofree(CH_CompressorState* state, const char* ID);

/**
 * Performs run-length encoding of the data array bits. The encoding forms
 * a stream of 16-bit unsigned integers. The first integer represents a
 * run of 0 bits, the next a run of 1 bits, etc.
 * 
 * @param count the number of ptr elements in the data array whose bits will]
 * be compressed with RLE.
 */
void compress_bit_runs(CH_CompressorState* state, uintptr_t* data, int count);

#endif
