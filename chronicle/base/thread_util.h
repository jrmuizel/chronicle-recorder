/*
    Copyright (c) 2006 Novell and contributors:
        robert@ocallahan.org
    
    Permission is hereby granted, free of charge, to any person
    obtaining a copy of this software and associated documentation
    files (the "Software"), to deal in the Software without
    restriction, including without limitation the rights to use,
    copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following
    conditions:
    
    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
    OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef THREAD_UTIL_H__
#define THREAD_UTIL_H__

/* Utility functions for working with pthreads */

#include <pthread.h>
#include <stdint.h>

/**
 * Simple semaphore implementation. 'outstanding_count' is always >= 0.
 */
typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  uint32_t outstanding_count;
} CH_Semaphore;

void semaphore_init(CH_Semaphore* sem);
/** Add one to outstanding_count. */
void semaphore_add(CH_Semaphore* sem);
/** Remove one from outstanding_count, waiting until it's > 0 if necessary. */
void semaphore_remove(CH_Semaphore* sem);
/** Wait for outstanding_count to reach 0. */
void semaphore_wait_for_all_removed(CH_Semaphore* sem);
void semaphore_destroy(CH_Semaphore* sem);

typedef void (* CH_ThreadProc)(void* closure);

/** Create a global thread pool. */
void init_threads(int num_worker_threads);
/**
 * Call 'fun' passing 'closure'. The call may occur on another thread,
 * or it may occur synchronously on this thread.
 * XXX this is *broken*. It's error prone. Everything that uses this should
 * be reexamined.
 */
void run_on_thread(CH_ThreadProc fun, void* closure);

#endif
