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

#ifndef DECOMPRESSION_CACHE_H_
#define DECOMPRESSION_CACHE_H_

#include <stdint.h>

#include "compressor.h"

/*
 * These functions are used to read and decompress a region of data from
 * the database. They can be implemented to cache the results of
 * decompression.
 */

/**
 * Read a block of data from the database, compressed with compression type
 * 'type', decompress it, and return the data. If 'len' is non-NULL,
 * the length of the decompressed data is stored there.
 * Returns NULL on failure.
 */
void* decompression_cache_acquire(uint64_t fileloc, uint32_t size,
                                  uint8_t type, uint32_t* len);
/**
 * Releases a block previously acquired via decompression_cache_acquire.
 */
void decompression_cache_release(uint64_t fileloc, void* data);

#endif /*DECOMPRESSION_CACHE_H_*/
