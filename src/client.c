/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#include <assert.h>
#include <string.h>
#include <time.h>
#include "client.h"

int bp_connection_post_handshake(bp_connection_s *connection)
{
	assert(connection->handsshaken == 0);
	connection->handsshaken = 1;
	
	if (connection->is_seed) {
		bp_connection_sendgetaddr(connection);
	}
	
	// Self-announce
	unsigned char addr_msg[31];
	memset(addr_msg, 0, 31);
	addr_msg[0] = 1;
	int t = time(0);
	memcpy(addr_msg+1, &t, 4);
	if (connection->server->program->relay_blocks)
		addr_msg[5] = 1;
	memcpy(addr_msg+13, connection->server->local_addr, 16);
	unsigned short local_port = ntohs(connection->server->local_port);
	memcpy(addr_msg+29, &local_port, 2);
	bp_connection_sendmessage(connection, addr_command, addr_msg, 31);
	
	// TODO: this MUST be moved.
	if (connection->server->program->relay_blocks)
		bp_connection_sendgetblocks(connection, NULL);
	
	return 0;
}