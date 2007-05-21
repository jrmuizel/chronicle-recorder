#include <stdio.h>
#include <unistd.h>

static long stackPtr;

int main(int argc, char** argv) {
  int foo;
  stackPtr = (long)&foo;
  printf("Stackptr is %p\n", &foo);
  return 0;
}
