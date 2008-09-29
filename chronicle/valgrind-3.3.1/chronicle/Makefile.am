include $(top_srcdir)/Makefile.tool.am

noinst_PROGRAMS = 
if VGP_X86_LINUX
noinst_PROGRAMS += chronicle-x86-linux
endif
if VGP_AMD64_LINUX
noinst_PROGRAMS += chronicle-amd64-linux
endif
if VGP_PPC32_LINUX
noinst_PROGRAMS += chronicle-ppc32-linux
endif

bin_PROGRAMS =
if VGP_X86_LINUX
bin_PROGRAMS += chronicle-indexer chronicle-query
endif
if VGP_AMD64_LINUX
bin_PROGRAMS += chronicle-indexer chronicle-query
endif
if VGP_PPC32_LINUX
bin_PROGRAMS += chronicle-indexer chronicle-query
endif

SOURCES_COMMON = main.c

chronicle_x86_linux_SOURCES      = $(SOURCES_COMMON)
chronicle_x86_linux_CPPFLAGS     = $(AM_CPPFLAGS_X86_LINUX)
chronicle_x86_linux_CFLAGS       = $(AM_CFLAGS_X86_LINUX)
chronicle_x86_linux_DEPENDENCIES = $(COREGRIND_LIBS_X86_LINUX)
chronicle_x86_linux_LDADD        = $(TOOL_LDADD_X86_LINUX)
chronicle_x86_linux_LDFLAGS      = $(TOOL_LDFLAGS_X86_LINUX)

chronicle_amd64_linux_SOURCES      = $(SOURCES_COMMON)
chronicle_amd64_linux_CPPFLAGS     = $(AM_CPPFLAGS_AMD64_LINUX)
chronicle_amd64_linux_CFLAGS       = $(AM_CFLAGS_AMD64_LINUX)
chronicle_amd64_linux_DEPENDENCIES = $(COREGRIND_LIBS_AMD64_LINUX)
chronicle_amd64_linux_LDADD        = $(TOOL_LDADD_AMD64_LINUX)
chronicle_amd64_linux_LDFLAGS      = $(TOOL_LDFLAGS_AMD64_LINUX)

chronicle_ppc32_linux_SOURCES      = $(SOURCES_COMMON)
chronicle_ppc32_linux_CPPFLAGS     = $(AM_CPPFLAGS_PPC32_LINUX)
chronicle_ppc32_linux_CFLAGS       = $(AM_CFLAGS_PPC32_LINUX)
chronicle_ppc32_linux_DEPENDENCIES = $(COREGRIND_LIBS_PPC32_LINUX)
chronicle_ppc32_linux_LDADD        = $(TOOL_LDADD_PPC32_LINUX)
chronicle_ppc32_linux_LDFLAGS      = $(TOOL_LDFLAGS_PPC32_LINUX)

SOURCES_BASE = \
	base/util.c \
	base/thread_util.c \
	base/json.c

SOURCES_INDEXER = \
	indexer/compressor.c \
	indexer/database_write.c \
	indexer/effect_map_write.c \
	indexer/indexer.c

SOURCES_QUERY = \
	query/database_read.c \
	query/debug.c \
	query/debug_dwarf2.c \
	query/decompression_cache.c \
	query/decompressor.c \
	query/effect_map_read.c \
	query/memory_map.c \
	query/query.c \
	query/reg_reconstruct.c

CFLAGS_CHRONICLE_TOOLS = -Ibase -D_GNU_SOURCE -Wall -g
LDFLAGS_CHRONICLE_TOOLS = -lz -lpthread -lelf

chronicle_indexer_SOURCES = $(SOURCES_BASE) $(SOURCES_INDEXER)
chronicle_indexer_CFLAGS  = $(CFLAGS_CHRONICLE_TOOLS)
chronicle_indexer_LDFLAGS = $(LDFLAGS_CHRONICLE_TOOLS)

chronicle_query_SOURCES = $(SOURCES_BASE) $(SOURCES_QUERY)
chronicle_query_CFLAGS  = $(CFLAGS_CHRONICLE_TOOLS)
chronicle_query_LDFLAGS = $(LDFLAGS_CHRONICLE_TOOLS)

