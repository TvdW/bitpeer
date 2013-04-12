/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#pragma once
#include "connection.h"

int bp_connection_readmessage(bp_connection_s *connection);

int bp_connection_sendversion(bp_connection_s *connection);
int bp_connection_readversion(bp_connection_s *connection);
int bp_connection_sendverack(bp_connection_s *connection);
int bp_connection_readverack(bp_connection_s *connection);

int bp_connection_sendgetaddr(bp_connection_s *connection);
int bp_connection_readgetaddr(bp_connection_s *connection);
//int bp_connection_sendaddr(bp_connection_s *connection);
int bp_connection_readaddr(bp_connection_s *connection);
int bp_connection_readinv(bp_connection_s *connection);
int bp_connection_readtx(bp_connection_s *connection);
int bp_connection_readblock(bp_connection_s *connection);
int bp_connection_sendgetdata(bp_connection_s *connection, int type, char *hash);
int bp_connection_readgetdata(bp_connection_s *connection);
int bp_connection_readgetblocks(bp_connection_s *connection);

extern const char version_command[], verack_command[], addr_command[], inv_command[],
	getdata_command[], notfound_command[], getblocks_command[], getheaders_command[],
	tx_command[], block_command[], headers_command[], getaddr_command[], checkorder_command[],
	submitorder_command[], ping_command[], pong_command[], reply_command[], alert_command[];