
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* Simple test program, no race.  Parent and child both modify x and
   use the hardware bus lock (implicitly, since XCHG r,m on x86/amd64
   does not require an explicit LOCK prefix.). */

#undef PLAT_x86_linux
#undef PLAT_amd64_linux
#undef PLAT_ppc32_linux
#undef PLAT_ppc64_linux
#undef PLAT_ppc32_aix5
#undef PLAT_ppc64_aix5

#if !defined(_AIX) && defined(__i386__)
#  define PLAT_x86_linux 1
#elif !defined(_AIX) && defined(__x86_64__)
#  define PLAT_amd64_linux 1
#elif !defined(_AIX) && defined(__powerpc__) && !defined(__powerpc64__)
#  define PLAT_ppc32_linux 1
#elif !defined(_AIX) && defined(__powerpc__) && defined(__powerpc64__)
#  define PLAT_ppc64_linux 1
#elif defined(_AIX) && defined(__64BIT__)
#  define PLAT_ppc64_aix5 1
#elif defined(_AIX) && !defined(__64BIT__)
#  define PLAT_ppc32_aix5 1
#endif


#if defined(PLAT_amd64_linux) || defined(PLAT_x86_linux)
#  define XCHG_M_R(_addr,_lval) \
     __asm__ __volatile__( \
        "xchgl %0, %1" \
        : /*out*/ "+r"(_lval) \
        : /*in*/  "m"(_addr) \
        : "memory", "cc" \
     )
#  define XCHG_M_R_with_redundant_LOCK(_addr,_lval) \
     __asm__ __volatile__( \
        "lock xchgl %0, %1" \
        : /*out*/ "+r"(_lval) \
        : /*in*/  "m"(_addr) \
        : "memory", "cc" \
     )
#else
#  define XCHG_M_R(_addr,_lval) \
      do { int tmp = *(int*)(& _addr); \
           *(int*)(& _addr) = (_lval); \
           _lval = tmp; \
      } while (0)
#  define XCHG_M_R_with_redundant_LOCK(_addr,_lval) \
      XCHG_M_R(_addr,_lval)
#endif

int x = 0;

void* child_fn ( void* arg )
{
   int v = 12345;
   XCHG_M_R_with_redundant_LOCK(x, v);
   assert(v == 0 || v == 6789);
   return NULL;
}

int main ( void )
{
   int v = 6789;
   pthread_t child;

   if (pthread_create(&child, NULL, child_fn, NULL)) {
      perror("pthread_create");
      exit(1);
   }

   XCHG_M_R(x, v);
   assert(v == 0 || v == 12345);

   if (pthread_join(child, NULL)) {
      perror("pthread join");
      exit(1);
   }

   if (v == 0 || v == 12345)
      printf("success\n");
   else
      printf("failure\n");

   return v;
}
