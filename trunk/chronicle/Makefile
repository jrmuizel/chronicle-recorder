VALGRIND = valgrind-3.2.3
BASE_OBJS = \
	base/thread_util.o \
	base/util.o \
	base/json.o \
	$(NULL)
INDEXER_OBJS = \
	indexer/indexer.o \
	indexer/compressor.o \
	indexer/database_write.o \
	indexer/effect_map_write.o \
	$(NULL)
QUERY_OBJS = \
	query/query.o \
	query/database_read.o \
	query/debug.o \
	query/debug_dwarf2.o \
	query/decompression_cache.o \
	query/decompressor.o \
	query/effect_map_read.o \
	query/memory_map.o \
	query/reg_reconstruct.o \
	$(NULL)
BINARIES = \
	chronicle-indexer \
	chronicle-query \
	$(VALGRIND)/chronicle/chronicle-x86-linux \
	$(NULL)
VALGRIND_DEPS = \
  $(VALGRIND)/chronicle/main.c \
  $(VALGRIND)/chronicle/arch.h \
  $(VALGRIND)/chronicle/effects.h \
  $(VALGRIND)/chronicle/log_stream.h \
  $(NULL)
TESTS = \
  tests/basic-function-calls.check \
  tests/fork.check \
  tests/registers.check \
  $(NULL)
TESTS_BIN = $(TESTS:.check=.bin)
TESTS_DB = $(TESTS:.check=.db)
TESTS_OK = $(TESTS:.check=.ok)

CFLAGS += -O2 -g -Wall
CFLAGS += -D_GNU_SOURCE
CFLAGS += -I$(VALGRIND)/chronicle -Ibase -Iindexer -Iquery -I/usr/include/libelf

LDFLAGS += -lz -lpthread -lelf

.PRECIOUS: %.db %.bin

all: $(BINARIES)

chronicle-indexer: $(BASE_OBJS) $(INDEXER_OBJS)
	$(CC) $(LDFLAGS) -o chronicle-indexer $(BASE_OBJS) $(INDEXER_OBJS)

chronicle-query: $(BASE_OBJS) $(QUERY_OBJS)
	$(CC) $(LDFLAGS) -o chronicle-query $(BASE_OBJS) $(QUERY_OBJS)

$(VALGRIND)/chronicle/chronicle-x86-linux: $(VALGRIND_DEPS)
	(cd $(VALGRIND); ./configure && make)

clean:
	rm -f $(BINARIES) $(BASE_OBJS) $(INDEXER_OBJS) $(QUERY_OBJS) \
	      $(TESTS_BIN) $(TESTS_DB) $(TESTS_OK)
	(cd $(VALGRIND); make clean)

distclean:
	rm -f $(BINARIES) $(BASE_OBJS) $(INDEXER_OBJS) $(QUERY_OBJS) \
	      $(TESTS_BIN) $(TESTS_DB) $(TESTS_OK)
	rm -rf base/.cdt* base/.project base/.setttings
	rm -rf query/.cdt* query/.project query/.setttings
	rm -rf indexer/.cdt* indexer/.project indexer/.setttings
	(cd $(VALGRIND); make distclean)

# Test framework

%.bin: %.c
	$(CC) -O0 -g -Wall $*.c -o $*.bin

%.db: %.bin chronicle-indexer $(VALGRIND)/chronicle/chronicle-x86-linux
	PATH=.:$(PATH) CHRONICLE_DB=$*.db VALGRIND_LIB=$(VALGRIND)/.in_place $(VALGRIND)/coregrind/valgrind --tool=chronicle $*.bin

%.ok: %.check %.db chronicle-query
	CHRONICLE_DB=$*.db $*.check
	touch $*.ok

check: $(TESTS_OK)

