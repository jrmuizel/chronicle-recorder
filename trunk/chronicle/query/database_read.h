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

#ifndef DATABASE_READ_H__
#define DATABASE_READ_H__

#include <stdint.h>

#include "database.h"

/**
 * Data structure to manage reading from a database.
 */
typedef struct {
  int            fd;

  CH_DBHeader    header;
  const char*    name_buf;
  CH_DBDirEntry* directory_buf;
} CH_DBFileReader;

/**
 * Prepare a database for reading. The file must already be open; we take
 * ownership of the file descriptor, so don't close it.
 */
void db_init_reader(CH_DBFileReader* db, int fd);

/**
 * Look up the database directory for an item with the given name.
 */
CH_DBDirEntry* db_directory_lookup(CH_DBFileReader* db, const char* name);

/**
 * Read a region from the database into the given buffer.
 */
void db_read(CH_DBFileReader* db, uint64_t offset, void* buf, uint32_t len);

/**
 * Read a region from the database and return the data in a freshly allocated
 * buffer.
 */
void* db_read_alloc(CH_DBFileReader* db, uint64_t offset, uint32_t len);

/* Currently there is no way to destroy a database reader or close the
 * file descriptor (other than by exiting the process, of course). */

#endif
