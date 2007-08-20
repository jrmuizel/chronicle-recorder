#include <stdio.h>
#include <unistd.h>
#include <errno.h>

static int local1(int a, int b) {
  puts("");
  return a + b;
}

static void call2() {
  puts("");
}

static int call1() {
  int foo = errno;
  call2();
  return foo;
}

int main(int argc, char** argv) {
  int a = call1();
  int b = local1(3, 5);
  return (a + b)/1000;
}
