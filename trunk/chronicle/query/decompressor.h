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

#ifndef DECOMPRESSOR_H_
#define DECOMPRESSOR_H_

/*
 * Decompression functions that can be used in conjunction with the
 * compression functions from compressor.h.
 */

#include <stdint.h>

/** Call this before using any functions in this file. */
void decompress_global_init();

/**
 * Decompress a compressed block in one shot.
 * @param type the type of the compressed data, as it was provided at
 * compression time.
 * @param len the length of the decompressed data
 * @return a malloced decompressed data block
 */
void* decompress_all(uint8_t* data, int size, uint8_t type, uint32_t* len);

/**
 * Skip to the end of a run-length-encoded block of 'count' bits.
 */
uint16_t* decompress_skip_bit_run_block(uint16_t* ptr, int count);

typedef struct {
  uint32_t offset;
  uint32_t length;
} CH_DecompressorBitRunRange;
/**
 * Given a pointer to a run-length-encoded block of bits, check whether
 * any bit in any of the given ranges is set.
 */
int decompress_check_any_set_in_bit_run_block(uint16_t* ptr,
    CH_DecompressorBitRunRange* ranges, int num_ranges);

#endif /*DECOMPRESSOR_H_*/
