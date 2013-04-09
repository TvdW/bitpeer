#include "program.h"

int bp_program_init(bp_program_s *program)
{
	program->network_magic = 0xD9B4BEF9;
	return 0;
}