#pragma once
#include <stdio.h>
#include "btcblock.h"

struct bp_blockstorage_fd_t {
	int fd;
	int offset;
	int size;
};
typedef struct bp_blockstorage_fd_t bp_blockstorage_fd_s;


struct bp_blockstorage_t {
	void *program;
	
	char *mainchain;
	char *orphans;
	void *mainindex;
	void *orphanindex;
	
	FILE* mainchain_fd;
	FILE* orphans_fd;
	unsigned int mainchain_allocsize;
	unsigned int mainchain_writepos;
	unsigned int orphans_allocsize;
	unsigned int orphans_writepos;
	
	int mainchain_height;
};
typedef struct bp_blockstorage_t bp_blockstorage_s;


int bp_blockstorage_init(bp_blockstorage_s *storage, void *program);
void bp_blockstorage_deinit(bp_blockstorage_s *storage);

int bp_blockstorage_store(bp_blockstorage_s *storage, char *blockhash, bp_btcblock_header_s *header, ev_uint64_t txn_count, bp_btcblock_tx_s *txs);
int bp_blockstorage_getfd(bp_blockstorage_s *storage, char *blockhash, bp_blockstorage_fd_s **fd);
int bp_blockstorage_index(bp_blockstorage_s *storage, char *blockhash, char *prevblock, unsigned int blockfile, unsigned int offset, unsigned int length, unsigned int checksum);
int bp_blockstorage_hasblock(bp_blockstorage_s *storage, char *blockhash);
int bp_blockstorage_reindex(bp_blockstorage_s *storage);
int bp_blockstorage_rehash(bp_blockstorage_s *storage);
char *bp_blockstorage_gettop(bp_blockstorage_s *storage);