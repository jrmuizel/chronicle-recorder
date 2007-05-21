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

#ifndef DATABASE_WRITE_H__
#define DATABASE_WRITE_H__

/* Code for writing a trace database */

#include <pthread.h>
#include <sys/uio.h>

#include "database.h"
#include "util.h"

/**
 * Data structure to represent a database open for writing. It has limited
 * support for concurrent writes by multiple threads.
 */
typedef struct {
  pthread_mutex_t mutex;
  int fd;

  CH_GrowBuf name_buf;
  CH_GrowBuf dir_buf;
  uint32_t name_buf_count;
  uint32_t dir_buf_count;
} CH_DBFile;

/**
 * Initialize a database for writing. fd must be already open for writing
 * to some file.
 */
void db_init(CH_DBFile* db, int fd);
/**
 * Perform a synchronous append to the database. We return the offset at
 * which the data was written. This can be performed by any thread.
 */
uint64_t db_append_sync(CH_DBFile* db, void* data, uintptr_t length);
/**
 * Perform a synchronous append of multiple data chunks to the database.
 * We return the offset at which the data was written. This can
 * be performed by any thread.
 */
uint64_t db_appendv_sync(CH_DBFile* db, const struct iovec* vector, int count);
/**
 * Add a directory entry to the database. This can only be performed
 * by the main thread.
 */
void db_add_directory_entry(CH_DBFile* db, const char* name, uint64_t offset,
			    uint64_t length);
/**
 * Write the final header and close the database. This can only be performed
 * by the main thread and all other threads must have stopped accessing
 * the database before this is called.
 */
void db_close(CH_DBFile* db, CH_DBHeader* header_template);

#endif
