/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#pragma once

struct bp_txpool_tx_t {
	unsigned int checksum;
	unsigned int length;
	char hash[32];
	char *data;
};
typedef struct bp_txpool_tx_t bp_txpool_tx_s;

struct bp_txpool_t {
	unsigned int size;
	unsigned int pos;
	bp_txpool_tx_s *transactions;
//	void *hashmap;
};
typedef struct bp_txpool_t bp_txpool_s;


int bp_txpool_init(bp_txpool_s *pool, int size);
void bp_txpool_deinit(bp_txpool_s *pool);

int bp_txpool_addtx_copy(bp_txpool_s *pool, char *tx, size_t tx_len);
int bp_txpool_addtx(bp_txpool_s *pool, char *tx, size_t tx_len);
bp_txpool_tx_s *bp_txpool_gettx(bp_txpool_s *pool, char *hash);
