#include <stdio.h>
#include <unistd.h>

static void is_child() {
    printf("I am the child\n");
}

static void is_parent() {
    printf("I am the parent\n");
}

int main(int argc, char** argv) {
  if (!fork()) {
    is_child();
  } else {
    is_parent();
  }
  return 0;
}
