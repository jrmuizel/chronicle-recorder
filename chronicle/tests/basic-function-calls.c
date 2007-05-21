#include <stdio.h>

static void print(void) {
  printf("Hello!\n");
}

int main(int argc, char** argv) {
  int i;
  for (i = 0; i < 5; ++i) {
    print();
  }
  return 0;
}
