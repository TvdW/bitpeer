#include <stdlib.h>
#include <string.h>
#include "connection.h"
#include "program.h"
#include "util.h"

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

static int bp_program_check_valid_ip(bp_proto_net_addr_full_s *ip, void *ctx)
{
	bp_program_s *program = ctx;
	if (bp_addrtype(ip->address) != 4) return -1;
	
	// Are we connected to this one already?
	for (int i = 0; i < program->max_connections; i++) {
		bp_connection_s *connection = program->connections[i];
		if (connection == NULL) continue;
		
		if (connection->remote_port == ip->port &&
			memcmp(connection->remote_addr, ip->address, 16) == 0)
		{
			return -1;
		}
	}
	
	// TODO: have we previously connected to this one
	
	return 0;
}

int bp_program_check_connections(bp_program_s *program)
{
	if (program->cur_connections < program->min_connections) {
		bp_proto_net_addr_full_s *ip;
		for (int i = 0; i < (program->min_connections - program->cur_connections); i++) {
			if (bp_addrpool_read(&program->addrpool, &ip, bp_program_check_valid_ip, program) < 0) {
				break;
			}
			
			struct sockaddr_in sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			memcpy(&sin.sin_addr, ip->address + 12, 4);
			sin.sin_port = ip->port;
			
			// Connect
			bp_connection_s *newconn = malloc(sizeof(bp_connection_s));
			if (bp_connection_connect(newconn, program->server_v4, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
				bp_connection_free(newconn);
			}
			
			printf("Connected to new client %u.%u.%u.%u:%u to get minimum connection #\n", (unsigned char)ip->address[12], (unsigned char)ip->address[13], (unsigned char)ip->address[14], (unsigned char)ip->address[15], ntohs(ip->port));
		}
	}
	
	return 0;
}