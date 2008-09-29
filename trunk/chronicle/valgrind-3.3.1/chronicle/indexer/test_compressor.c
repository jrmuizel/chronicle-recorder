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

#include <stdio.h>
#include <unistd.h>

#include "compressor.h"

int main() {
  CH_CompressorState state;
  char buf[1024];
  size_t bytes_read;
  size_t compressed_bytes = 0;

  compress_global_init();
  compress_init(&state, CH_COMPRESSTYPE_DATA);
  while ((bytes_read = read(0, buf, sizeof(buf))) > 0) {
    compress_data(&state, buf, bytes_read);
    compressed_bytes += bytes_read;
  }
  compress_done(&state);
  write(1, state.output.data, state.output_len);
  compress_finish(&state, NULL);
  return 0;
}
