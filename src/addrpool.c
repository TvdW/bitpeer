/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "addrpool.h"
#include "program.h"

int bp_addrpool_init(bp_addrpool_s *pool, void *_program)
{
	bp_program_s *program = _program;
	
	pool->program = program;
	pool->raw_storage = malloc(program->addrpool_size * 30);
	assert(pool->raw_storage);
	memset(pool->raw_storage, 0, program->addrpool_size * 30);
	pool->size = program->addrpool_size;
	pool->fillsize = 0;
	pool->readpos = 0;
	
	return 0;
}

void bp_addrpool_deinit(bp_addrpool_s *pool)
{
	free(pool->raw_storage);
}

int bp_addrpool_add(bp_addrpool_s *pool, bp_proto_net_addr_full_s *entry)
{
	int i;
	for (i = 0; i < pool->size; i++) {
		bp_proto_net_addr_full_s *cur = (bp_proto_net_addr_full_s*)(((char*)pool->raw_storage) + (30 * i));
		
		if (cur->time == 0) {
			memcpy(cur, entry, 30);
			if (pool->fillsize < pool->size) pool->fillsize += 1;
			return 0;
		}
	}
	
	return -1;
}

int bp_addrpool_read(bp_addrpool_s *pool, bp_proto_net_addr_full_s **target, int validator(bp_proto_net_addr_full_s *entry, void *ctx), void *ctx)
{
	if (pool->fillsize == 0) return -1;
	
	int i;
	for (i = 0; i < pool->size; i++) {
		int pos = (i + pool->readpos) % pool->size;
		if (pos > pool->fillsize) continue;
		
		bp_proto_net_addr_full_s *entry = ((bp_proto_net_addr_full_s*)pool->raw_storage) + pos;
		if (validator(entry, ctx) == 0) {
			*target = entry;
			pool->readpos = (pos + 1) % pool->size;
			return 0;
		}
	}
	
	return -1;
}

int bp_addrpool_hasaddr(bp_addrpool_s *pool, bp_proto_net_addr_full_s *addr)
{
	for (int i = 0; i < pool->fillsize; i++) {
		bp_proto_net_addr_full_s *entry = ((bp_proto_net_addr_full_s*)pool->raw_storage) + i;
		if (memcmp(entry->address, addr, 16) == 0) return 1;
	}
	
	return 0;
}