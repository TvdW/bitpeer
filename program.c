#include "program.h"

int bp_program_init(bp_program_s *program)
{
	program->network_magic = 0xD9B4BEF9;
	bp_addrpool_init(&program->addrpool, program);
	return 0;
}

void bp_program_deinit(bp_program_s *program)
{
	bp_addrpool_deinit(&program->addrpool);
}