/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#pragma once
#include <event2/listener.h>
#include "program.h"

struct bp_server_t {
	char local_addr[16];
	unsigned short local_port;
	
	bp_program_s *program;
	struct evconnlistener *listener;
};
typedef struct bp_server_t bp_server_s;


int bp_server_init(bp_server_s *server, bp_program_s *program, int family, char *address, unsigned short port);
int bp_server_deinit(bp_server_s *server);
int bp_server_listen(bp_server_s *server, unsigned short port);