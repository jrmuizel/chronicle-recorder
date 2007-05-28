#include <stdio.h>
#include <unistd.h>

static void passStackPtr2(long ptr) {
  printf("Stackptr2: %p\n", (void*)ptr);
}

static void printStackPtr2() {
  int foo;
  passStackPtr2(&foo);
}

static void passStackPtr(long ptr) {
  printf("Stackptr: %p\n", (void*)ptr);
}

static void printStackPtr() {
  int foo;
  passStackPtr(&foo);
  printStackPtr2();
}

int main(int argc, char** argv) {
  printStackPtr();
  return 0;
}
