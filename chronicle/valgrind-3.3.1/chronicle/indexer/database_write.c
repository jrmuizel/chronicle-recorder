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

#include "database_write.h"
#include "log_stream.h"
#include "util.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void db_init(CH_DBFile* db, int fd) {
  CH_DBHeader header;
  int64_t r;

  db->fd = fd;
  pthread_mutex_init(&db->mutex, NULL);

  db->name_buf.data = NULL;
  db->name_buf.size = 0;
  db->dir_buf.data = NULL;
  db->dir_buf.size = 0;

  memset(&header, 0, sizeof(header));
  strcpy(header.magic, "ChronicleDB");
  r = write(db->fd, &header, sizeof(header));
  if (r != sizeof(header)) {
    perror("Cannot write header");
    exit(12);
  }
}

static uint64_t db_append_sync_unlocked(CH_DBFile* db, uint8_t* data,
					uintptr_t length) {
  int64_t offset;
  intptr_t written;

  offset = lseek64(db->fd, 0, SEEK_END);
  if (offset < 0) {
    perror("cannot seek to EOF");
    exit(12);
  }
  written = write(db->fd, data, length);
  if (written != length) {
    if (written < 0) {
      perror("Cannot write to db");
      exit(13);
    }
    fprintf(stderr, "Failed to write %d bytes (did %d)\n",
	    (int)length, (int)written);
    exit(12);
  }
  return (uint64_t)offset;
}

static uint64_t db_appendv_sync_unlocked(CH_DBFile* db,
					 const struct iovec* vector,
					 int count) {
  int64_t offset;
  intptr_t written;
  intptr_t length = 0;
  int i;

  for (i = 0; i < count; ++i) {
    length += vector[i].iov_len;
  }

  offset = lseek64(db->fd, 0, SEEK_END);
  if (offset < 0) {
    perror("cannot seek to EOF");
    exit(12);
  }
  written = writev(db->fd, vector, count);
  if (written != length) {
    if (written < 0) {
      perror("Cannot write to db");
      exit(13);
    }
    fprintf(stderr, "Failed to write %d bytes (did %d)\n",
	    (int)length, (int)written);
    exit(12);
  }
  return (uint64_t)offset;
}

uint64_t db_append_sync(CH_DBFile* db, void* data, uintptr_t length) {
  uint64_t offset;

  pthread_mutex_lock(&db->mutex);
  offset = db_append_sync_unlocked(db, data, length);
  pthread_mutex_unlock(&db->mutex);
  return offset;
}

uint64_t db_appendv_sync(CH_DBFile* db, const struct iovec* vector,
			 int count) {
  uint64_t offset;

  pthread_mutex_lock(&db->mutex);
  offset = db_appendv_sync_unlocked(db, vector, count);
  pthread_mutex_unlock(&db->mutex);
  return offset;
}

static void write_directory(CH_DBFile* db, CH_DBHeader* header_template) {
  CH_DBHeader header = *header_template;
  int64_t r;

  strcpy(header.magic, "ChronicleDB");
  header.version = CH_DB_VERSION;
#ifdef CH_X86
  header.is_little_endian = 1;
#if __WORDSIZE == 64
  header.architecture = CH_ARCH_AMD64;
#else
  header.architecture = CH_ARCH_X86;
#endif
#else
#error Unsupported architecture
#endif
  memset(header.reserved_zero, 0, sizeof(header.reserved_zero));

  header.directory_offset =
    db_append_sync(db, db->dir_buf.data,
		   sizeof(CH_DBDirEntry)*db->dir_buf_count);
  header.directory_count = db->dir_buf_count;
  header.name_offset =
    db_append_sync(db, db->name_buf.data, db->name_buf_count);
  header.name_size = db->name_buf_count;

  r = lseek64(db->fd, 0, SEEK_SET);
  if (r < 0) {
    perror("Cannot seek to start of file");
    exit(12);
  }
  r = write(db->fd, &header, sizeof(header));
  if (r != sizeof(header)) {
    perror("Cannot write header");
    exit(12);
  }
}

void db_close(CH_DBFile* db, CH_DBHeader* header_template) {
  int r;

  write_directory(db, header_template);

  r = close(db->fd);
  if (r < 0) {
    perror("Cannot close fd");
  }
}

void db_add_directory_entry(CH_DBFile* db, const char* name, uint64_t offset,
			    uint64_t length) {
  uint32_t name_len = strlen(name) + 1;
  uint32_t name_offset = db->name_buf_count;
  uint32_t entry_num = db->dir_buf_count;
  CH_DBDirEntry* entry;

  ensure_buffer_size(&db->name_buf, db->name_buf_count + name_len);
  memcpy(db->name_buf.data + db->name_buf_count, name, name_len);
  db->name_buf_count += name_len;

  db->dir_buf_count = entry_num + 1;
  ensure_buffer_size(&db->dir_buf, sizeof(CH_DBDirEntry)*db->dir_buf_count);
  entry = &((CH_DBDirEntry*)db->dir_buf.data)[entry_num];
  entry->offset = offset;
  entry->length = length;
  entry->name_offset = name_offset;
}
