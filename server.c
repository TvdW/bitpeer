#include <string.h>
#include "server.h"

int bp_server_init(bp_server_s *server, bp_program_s *program, int family, char *address, unsigned short port)
{
	server->program = program;
	
	server->local_port = port;
	if (family == 4) {
		memset(server->local_addr, 0, 10);
		memcpy(server->local_addr + 12, address, 4);
		server->local_addr[10] = 0xFF;
		server->local_addr[11] = 0xFF;
	}
	else {
		memcpy(server->local_addr, address, 16);
	}
	
	return 0;
}

int bp_server_deinit(bp_server_s *server)
{
	return 0;
}