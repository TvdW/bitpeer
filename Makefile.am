EXTRA_DIST = README.md LICENSE.txt

AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

bin_PROGRAMS = bitpeer
bitpeer_SOURCES = \
	src/bitpeer.c \
	src/addrpool.h src/addrpool.c \
	src/blockstorage.h src/blockstorage.c src/blockstorage_rechain.c \
	src/blockverify.h src/blockverify.c \
	src/btcblock.h \
	src/client.h src/client.c \
	src/commands.h src/commands.c \
	src/connection.h src/connection.c \
	src/log.h src/log.c \
	src/program.h src/program.c \
	src/server.h src/server.c \
	src/txpool.h src/txpool.c \
	src/txverify.h src/txverify.c \
	src/util.h src/util.c \
	src/invvector.h src/invvector.c
bitpeer_CFLAGS = -Wall -Werror -pedantic -Wno-strict-aliasing -Wmissing-prototypes