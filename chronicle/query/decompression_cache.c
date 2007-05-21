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

#include "decompression_cache.h"
#include "util.h"
#include "database.h"
#include "query.h"
#include "decompressor.h"

void* decompression_cache_acquire(uint64_t fileloc, uint32_t size,
                                  uint8_t type, uint32_t* len) {
  void* compressed = db_read_alloc(get_db(), fileloc, size);
  void* result = decompress_all(compressed, size, type, len);
  safe_free(compressed);
  return result;
}

void decompression_cache_release(uint64_t fileloc, void* data) {
  safe_free(data);
}
