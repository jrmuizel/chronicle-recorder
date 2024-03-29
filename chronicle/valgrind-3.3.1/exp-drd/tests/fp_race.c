/*
  This file is part of drd, a data race detector.

  Copyright (C) 2006-2007 Bart Van Assche
  bart.vanassche@gmail.com

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

// Test data race detection between floating point variables.

#include <assert.h>
#include <stdio.h>      // printf()
#include <pthread.h>
#include <unistd.h>    // usleep()
#include "../drd_clientreq.h"


// Local functions declarations.

static void* thread_func(void*);

// Local variables.

// s_mutex protects s_d3.
static pthread_mutex_t s_mutex;

static double s_d1; // accessed before thread creation and in the created
                    // thread (not a race).
static double s_d2; // accessed in the created thread and after the join
                    // (not a race).
static double s_d3; // accessed simultaneously from both threads (race).
static int    s_debug     = 0;
static int    s_do_printf = 0;
static int    s_use_mutex = 0;


// Function definitions.

static void set_thread_name(const char* const name)
{
  int res;
  VALGRIND_DO_CLIENT_REQUEST(res, 0, VG_USERREQ__SET_THREAD_NAME,
                             name, 0, 0, 0, 0);
}

int main(int argc, char** argv)
{
  int optchar;
  pthread_t threadid;

  set_thread_name("main");

  while ((optchar = getopt(argc, argv, "dmp")) != EOF)
  {
    switch (optchar)
    {
    case 'd':
      s_debug = 1;
      break;
    case 'm':
      s_use_mutex = 1;
      break;
    case 'p':
      s_do_printf = 1;
      break;
    default:
      assert(0);
    }
  }

  pthread_mutex_init(&s_mutex, 0);

  // Switch to line-buffered mode, such that timing information can be 
  // obtained for each printf() call with strace.
  setlinebuf(stdout);

  if (s_debug)
  {
    printf("&s_d1 = %p; &s_d2 = %p; &s_d3 = %p\n", &s_d1, &s_d2, &s_d3);
  }

  s_d1 = 1;
  s_d3 = 3;

  pthread_create(&threadid, 0, thread_func, 0);
  // Wait until the printf() in the created thread finished.

  {
    if (s_use_mutex) pthread_mutex_lock(&s_mutex);
    s_d3++;
    if (s_use_mutex) pthread_mutex_unlock(&s_mutex);
  }

  // Wait until the thread finished.
  //printf("Before call to pthread_join()\n");
  //fflush(stdout);
  pthread_join(threadid, 0);
  //printf("After call to pthread_join()\n");
  //fflush(stdout);
  if (s_do_printf) printf("s_d2 = %g (should be 2)\n", s_d2);
  if (s_do_printf) printf("s_d3 = %g (should be 5)\n", s_d3);

  pthread_mutex_destroy(&s_mutex);

  return 0;
}

static void* thread_func(void* thread_arg)
{
  set_thread_name("thread_func");

  if (s_do_printf)
  {
    printf("s_d1 = %g (should be 1)\n", s_d1);
  }
  s_d2 = 2;
  {
    if (s_use_mutex) pthread_mutex_lock(&s_mutex);
    s_d3++;
    if (s_use_mutex) pthread_mutex_unlock(&s_mutex);
  }
  return 0;
}
