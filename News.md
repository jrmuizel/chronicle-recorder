# News #

## 29/9/08: Updated build system ##

I updated the build system and file layout so that all the Chronicle helper apps and tests are built as part of the Valgrind build. This simplifies things somewhat and also makes proper Chronicle installation happen on "make install". The Build page has been updated with the new instructions.

## 29/9/08: Updated to Valgrind 3.3.1 ##

## 16/8/07: New features ##

I added a "scanCount" command to the query engine to count the number of memory effects in a given memory and timestamp range.

I also made "findSourceInfo" accept a range of addresses and return one source information record for each address. This allows efficient lookup over many addresses.

Both of these features were motivated by the Eclipse UI I'm developing.

## 27/7/07: Bug fixes, contributions ##

Andrew Sutherland has announced some tools he's building on Chronicle! See http://www.visophyte.org/blog/2007/07/26/chroniquery-chronicle-recorder-and-python-boogie-down/. He has some Chronicle patches that I hope to integrate shortly.

Also I've recently checked in some small fixes of my own. I fixed some small bugs, and the query engine's chronicle-log.NNN logs now include query output as well as query input.

## 10/6/07: Removed "featured" download ##

I notice that people continue to download the tarball at a slow but steady rate. (I find that surprising since it doesn't do anything generally useful, but fine!) People really should pull the latest version from Subversion since it fixes the issues discussed below, so I made the tarball no longer a "featured download" to try to discourage it.

## 28/5/07: Fixed Ubuntu build ##

I checked in a patch by Grahame Bowland that fixes the build on Ubuntu. I also removed some generated files that should not be part of the repository. I noticed that make check fails because the register test was incomplete; I've fixed the test, but it's still failing and I don't know why right now. I'll look into it later. Thanks Grahame!

Update: I found the problem with registers.check and checked in a fix. "make check" should pass fine now.

## 22/5/07: Subversion repository created ##

I have checked the sources into Subversion (see the Source tab). This is basically the same as the initial tarball, but I have added a couple of small fixes (one to clean up spurious error messages when a process is forked, one to allow Chronicle to build on systems where gelf.h is in /usr/include instead of /usr/include/libelf).