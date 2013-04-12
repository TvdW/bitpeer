/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include "txpool.h"

int bp_txpool_init(bp_txpool_s *pool, int size)
{
	pool->size = size;
	pool->pos = 0;
	pool->transactions = malloc(size * sizeof(bp_txpool_tx_s));
	memset(pool->transactions, 0, size * sizeof(bp_txpool_tx_s));
	
	return 0;
}

void bp_txpool_deinit(bp_txpool_s *pool)
{
	int i;
	for (i = 0; i < pool->size; i++) {
		if (pool->transactions[i].data) {
			free(pool->transactions[i].data);
		}
	}
}

int bp_txpool_addtx(bp_txpool_s *pool, char *tx, size_t tx_len)
{
	bp_txpool_tx_s *entry = &pool->transactions[pool->pos];
	if (entry->data) free(entry->data);
	entry->data = tx;
	entry->length = tx_len;
	
	unsigned char hash1[SHA256_DIGEST_LENGTH];
	unsigned char hash2[SHA256_DIGEST_LENGTH];
	SHA256((unsigned char*)tx, tx_len, hash1);
	SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
	memcpy(entry->hash, hash2, 32);
	entry->checksum = *(unsigned int*)(hash2);
	
	pool->pos = (pool->pos + 1) % pool->size;
	
	return 0;
}

int bp_txpool_addtx_copy(bp_txpool_s *pool, char *tx, size_t tx_len)
{
	char *copy = malloc(tx_len);
	memcpy(copy, tx, tx_len);
	return bp_txpool_addtx(pool, copy, tx_len);
}

bp_txpool_tx_s *bp_txpool_gettx(bp_txpool_s *pool, char *hash)
{
	// TODO: This is just horrible.
	
	int i;
	for (i = 0; i < pool->size; i++) {
		if (memcmp(pool->transactions[i].hash, hash, 32) == 0) {
			return &pool->transactions[i];
		}
	}
	
	return NULL;
}
