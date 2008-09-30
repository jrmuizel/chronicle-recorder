#include <fenv.h>
#include <stdlib.h>

static void end() {
  exit(0);
}

int main(int argc, char **argv) {
  feclearexcept(FE_ALL_EXCEPT);
  end();
}

