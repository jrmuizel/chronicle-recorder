# Build #

Chronicle is packaged as a modified Valgrind. It requires a few devel packages to be installed. Packages you might need, depending on distro:
  * libc6-dev (Ubuntu)
  * libc6-dev-i386 (Ubuntu 64-bit)
  * libelf (SUSE)
  * elfutils-libelf-devel (Red Hat)
  * libelfg0-dev (Ubuntu)

Check it out from Subversion trunk (do not download the initial code drop, since it is very old and won't work). Then, to install it in $HOME/bin,
```
cd valgrind-3.3.1
./configure --prefix=$HOME && make install
```

Then to run the Chronicle tests,
```
make check
```

To apply Chronicle to your own program, run
```
CHRONICLE_DB=/tmp/ls.db valgrind --tool=chronicle ls
```
(This assumes 'make install' installed 'valgrind' somewhere in your $PATH. If not, you'll need to launch to the installed 'valgrind' using its full path.)

To start chronicle-query and issue [JSON queries](http://chronicle-recorder.googlecode.com/svn/trunk/chronicle/valgrind-3.3.1/chronicle/docs/protocol.html):
```
chronicle-query --db /tmp/ls.db
```

Ordinarily you would not start chronicle-query directly, but instead use a higher-level tool such as [Chronomancer](http://code.google.com/p/chronomancer).

Chronicle is currently based on Valgrind 3.3.1. Chronicle requires the x86 or AMD64 architectures on Linux, but should be fairly easy to port to any platform Valgrind itself supports.