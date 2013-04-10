#include <stdlib.h>
#include <string.h>
#include "program.h"

int bp_program_init(bp_program_s *program)
{
	program->network_magic = 0xD9B4BEF9;
	program->connections = malloc(program->max_connections * sizeof(void*));
	memset(program->connections, 0, program->max_connections * sizeof(void*));
	bp_addrpool_init(&program->addrpool, program);
	bp_blockstorage_init(&program->blockstorage, program);
	bp_txpool_init(&program->txpool, program->txpool_size);
	return 0;
}

void bp_program_deinit(bp_program_s *program)
{
	bp_addrpool_deinit(&program->addrpool);
	bp_blockstorage_deinit(&program->blockstorage);
	bp_txpool_deinit(&program->txpool);
}