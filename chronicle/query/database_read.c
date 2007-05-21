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

#include "database_read.h"

#include "util.h"

#include <sys/types.h>
#include <unistd.h>
#include <string.h>

void db_init_reader(CH_DBFileReader* db, int fd) {
  db->fd = fd;

  db_read(db, 0, &db->header, sizeof(db->header));
  if (db->header.version != CH_DB_VERSION)
    fatal_error(33, "Database is not the current version");
  
  db->name_buf = db_read_alloc(db, db->header.name_offset,
			       db->header.name_size);
  db->directory_buf =
    db_read_alloc(db, db->header.directory_offset,
		  db->header.directory_count*sizeof(CH_DBDirEntry));
}

CH_DBDirEntry* db_directory_lookup(CH_DBFileReader* db, const char* name) {
  int i;
  for (i = 0; i < db->header.directory_count; ++i) {
    const char* n = db->name_buf + db->directory_buf[i].name_offset;
    if (strcmp(n, name) == 0)
      return &db->directory_buf[i];
  }
  return NULL;
}

void db_read(CH_DBFileReader* db, uint64_t offset, void* buf, uint32_t len) {
  while (len > 0) {
    ssize_t r = pread64(db->fd, buf, len, offset);
    if (r <= 0)
      fatal_perror(21, "Cannot read database file at %lx length %d\n",
		   offset, len);

    offset += r;
    buf = (uint8_t*)buf + r;
    len -= r;
  }
}

void* db_read_alloc(CH_DBFileReader* db, uint64_t offset, uint32_t len) {
  void* buf = safe_malloc(len);
  db_read(db, offset, buf, len);
  return buf;
}
