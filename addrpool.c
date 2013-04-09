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
		bp_proto_net_addr_full_s *cur = pool->raw_storage + (30 * i);
		
		if (cur->time == 0) {
			memcpy(cur, entry, 30);
			pool->fillsize += 1;
			return 0;
		}
	}
	
	return -1;
}