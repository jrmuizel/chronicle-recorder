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

#include "thread_util.h"
#include "config.h"
#include "util.h"

#include <stdio.h>

void semaphore_init(CH_Semaphore* sem) {
  pthread_mutex_init(&sem->mutex, NULL);
  pthread_cond_init(&sem->condition, NULL);
  sem->outstanding_count = 0;
}

void semaphore_add(CH_Semaphore* sem) {
  pthread_mutex_lock(&sem->mutex);
  sem->outstanding_count++;
  pthread_mutex_unlock(&sem->mutex);
}

void semaphore_remove(CH_Semaphore* sem) {
  pthread_mutex_lock(&sem->mutex);
  sem->outstanding_count--;
  if (sem->outstanding_count == 0) {
    pthread_cond_broadcast(&sem->condition);
  }
  pthread_mutex_unlock(&sem->mutex);
}

void semaphore_wait_for_all_removed(CH_Semaphore* sem) {
  pthread_mutex_lock(&sem->mutex);
  while (sem->outstanding_count > 0) {
    pthread_cond_wait(&sem->condition, &sem->mutex);
  }
  pthread_mutex_unlock(&sem->mutex);
}

void semaphore_destroy(CH_Semaphore* sem) {
  pthread_mutex_destroy(&sem->mutex);
  pthread_cond_destroy(&sem->condition);
}


typedef struct {
  CH_ThreadProc fun;
  void* closure;
} WorkEntry;
static pthread_t* workers;
static WorkEntry work;
static pthread_mutex_t work_mutex;
static int waiting_workers;
static pthread_cond_t work_available_condition;

static void* thread_run(void* params) {
  for (;;) {
    WorkEntry w;

    pthread_mutex_lock(&work_mutex);
    w = work;
    work.fun = NULL;
    if (!w.fun) {
      ++waiting_workers;
      pthread_cond_wait(&work_available_condition, &work_mutex);
      --waiting_workers;
    }
    pthread_mutex_unlock(&work_mutex);

    if (w.fun) {
      w.fun(w.closure);
    }
  }
  return 0;
}

void init_threads(int num_worker_threads) {
  int i;

  workers = safe_malloc(sizeof(pthread_t)*num_worker_threads);

  pthread_mutex_init(&work_mutex, NULL);
  pthread_cond_init(&work_available_condition, NULL);
  for (i = 0; i < 1; ++i) {
    pthread_create(&workers[i], NULL, thread_run, NULL);
  }
  waiting_workers = i;
}

void run_on_thread(CH_ThreadProc fun, void* closure) {
  int done = 0;
/*
  pthread_mutex_lock(&work_mutex);
  if (!work.fun && waiting_workers) {
    work.fun = fun;
    work.closure = closure;
    done = 1;
  } else {
    pthread_cond_signal(&work_available_condition);
  }
  pthread_mutex_unlock(&work_mutex);
*/
  if (!done) {
    /* if no thread is available, run synchronously */
    fun(closure);
  }
}
