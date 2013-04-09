#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "addrpool.h"
#include "program.h"

int bp_addrpool_init(bp_addrpool_s *pool, void *_program)
{
	bp_program_s *program = _program;
	pool->program = program;
	
	// Allocate the pools
	int poolsize = 0;
	poolsize += sizeof(bp_addrpool_addr4_s) * program->addrpool_v4count;
	poolsize += sizeof(bp_addrpool_addr6_s) * program->addrpool_v6count;
	
	char* allocated_pool = malloc(poolsize);
	assert(allocated_pool != NULL);
	
	pool->raw_storage = allocated_pool;
	pool->v4pointer = 0;
	pool->v6pointer = 0;
	pool->v4pool = (bp_addrpool_addr4_s*)allocated_pool;
	pool->v6pool = (bp_addrpool_addr6_s*)(allocated_pool + (sizeof(bp_addrpool_addr4_s) * program->addrpool_v4count));
	pool->v4size = program->addrpool_v4count;
	pool->v6size = program->addrpool_v6count;
	
	return 0;
}

void bp_addrpool_deinit(bp_addrpool_s *pool)
{
	free(pool->raw_storage);
}

int bp_addrpool_add(bp_addrpool_s *pool, int family, char *address, unsigned short port, unsigned int last_seen)
{
	// TODO: check duplicates
	// TODO: also allow replacing old ones
	if (last_seen == 0) last_seen = 1; // We don't want bugs
	
	int i, pos;
	
	if (family == 4) {
		for (i = 0; i < pool->v4size; i++) {
			pos = (i + pool->v4pointer) % pool->v4size;
			if (pool->v4pool[pos].last_seen == 0) {
				pool->v4pool[pos].last_seen = last_seen;
				memcpy(pool->v4pool[pos].address, address, 4);
				pool->v4pool[pos].port = port;
				pool->v4pointer = pos;
				return 0;
			}
		}
	}
	
	else {
		for (i = 0; i < pool->v6size; i++) {
			pos = (i + pool->v6pointer) % pool->v6size;
			if (pool->v6pool[pos].last_seen == 0) {
				pool->v6pool[pos].last_seen = last_seen;
				memcpy(pool->v6pool[pos].address, address, 16);
				pool->v6pool[pos].port = port;
				pool->v6pointer = pos;
				return 0;
			}
		}
	}
	
	return -1;
}