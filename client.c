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
	addr_msg[5] = 1;
	memcpy(addr_msg+13, connection->server->local_addr, 16);
	memcpy(addr_msg+29, &connection->server->local_port, 2);
	bp_connection_sendmessage(connection, addr_command, addr_msg, 31);
	
	return 0;
}