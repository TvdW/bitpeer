/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#include <stdlib.h>
#include <string.h>
#include "connection.h"
#include "program.h"
#include "util.h"
#include "log.h"

#define RECENT_CONNECT_SIZE 512

int bp_program_init(bp_program_s *program)
{
	program->network_magic = 0xD9B4BEF9;
	program->connections = malloc(program->max_connections * sizeof(void*));
	memset(program->connections, 0, program->max_connections * sizeof(void*));
	bp_addrpool_init(&program->addrpool, program);
	
	if (program->relay_blocks)
		bp_blockstorage_init(&program->blockstorage, program);
	if (program->relay_transactions)
		bp_txpool_init(&program->txpool, program->txpool_size);
	
	program->recent_connects = malloc(RECENT_CONNECT_SIZE * 18);
	memset(program->recent_connects, 0, RECENT_CONNECT_SIZE * 18);
	program->recent_connects_pos = 0;
	return 0;
}

void bp_program_deinit(bp_program_s *program)
{
	for (int i = 0; i < program->max_connections; i++) {
		if (program->connections[i] != NULL)
			bp_connection_free(program->connections[i]);
	}
	
	free(program->connections);
	bp_addrpool_deinit(&program->addrpool);
	
	if (program->relay_blocks)
		bp_blockstorage_deinit(&program->blockstorage);
	if (program->relay_transactions)
		bp_txpool_deinit(&program->txpool);
	
	free(program->recent_connects);
}

static int bp_program_check_valid_ip(bp_proto_net_addr_full_s *ip, void *ctx)
{
	bp_program_s *program = ctx;
	if (bp_addrtype(ip->address) != 4) return -1;
	
	// Are we connected to this one already?
	for (int i = 0; i < program->max_connections; i++) {
		bp_connection_s *connection = program->connections[i];
		if (connection == NULL) continue;
		
		if (connection->remote_port == ntohs(ip->port) &&
			memcmp(connection->remote_addr, ip->address, 16) == 0)
		{
			return -1;
		}
	}
	
	// Have we recently connected?
	for (int i = 0; i < RECENT_CONNECT_SIZE; i++) {
		if (memcmp(ip->address, program->recent_connects + (18 * i), 18) == 0) {
			return -1;
		}
	}
	
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
			
			write_log(2, "Connected to new client %u.%u.%u.%u:%u to get minimum connection count", (unsigned char)ip->address[12], (unsigned char)ip->address[13], (unsigned char)ip->address[14], (unsigned char)ip->address[15], ntohs(ip->port));
			
			// Write it in our pool
			memcpy(program->recent_connects + (18 * program->recent_connects_pos), ip->address, 18);
			program->recent_connects_pos = (program->recent_connects_pos + 1) % RECENT_CONNECT_SIZE;
		}
	}
	
	return 0;
}