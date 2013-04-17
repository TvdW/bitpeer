/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "addrpool.h"

int bp_addrpool_init(bp_addrpool_s *pool, unsigned int size)
{
	pool->raw_storage = malloc(size * 30);
	assert(pool->raw_storage);
	memset(pool->raw_storage, 0, size * 30);
	pool->size = size;
	pool->writepos = 0;
	pool->readpos = 0;
	pool->count = 0;
	
	return 0;
}

void bp_addrpool_deinit(bp_addrpool_s *pool)
{
	free(pool->raw_storage);
}

int bp_addrpool_add(bp_addrpool_s *pool, bp_proto_net_addr_full_s *entry)
{
	memcpy(pool->raw_storage + (30 * pool->writepos), entry, 30);
	pool->writepos = (pool->writepos + 1) % pool->size;
	if (pool->count < pool->size) pool->count += 1;
	
	return 0;
}

int bp_addrpool_read(bp_addrpool_s *pool, bp_proto_net_addr_full_s **target, int validator(bp_proto_net_addr_full_s *entry, void *ctx), void *ctx)
{
	if (pool->count == 0) return -1;
	
	for (int i = 0; i < pool->count; i++) {
		int pos = (i + pool->readpos) % pool->count;
		
		bp_proto_net_addr_full_s *entry = ((bp_proto_net_addr_full_s*)pool->raw_storage) + pos;
		if (validator(entry, ctx) == 0) {
			*target = entry;
			pool->readpos = (pos + 1) % pool->count;
			return 0;
		}
	}
	
	return -1;
}

int bp_addrpool_hasaddr(bp_addrpool_s *pool, bp_proto_net_addr_full_s *addr)
{
	// TODO: this is slow
	
	for (int i = 0; i < pool->count; i++) {
		bp_proto_net_addr_full_s *entry = ((bp_proto_net_addr_full_s*)pool->raw_storage) + i;
		if (memcmp(entry->address, addr->address, 16) == 0) return 1;
	}
	
	return 0;
}