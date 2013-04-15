/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#include <string.h>
#include <stdlib.h>
#include <event2/event.h>
#include "connection.h"
#include "server.h"
#include "log.h"
#include "util.h"

static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd,
						   struct sockaddr *address, int socklen, void* ctx);

int bp_server_init(bp_server_s *server, bp_program_s *program, char *address, unsigned short port)
{
	server->listener = NULL;
	server->program = program;
	
	server->local_port = port;
	memcpy(server->local_addr, address, 16);
	
	return 0;
}

int bp_server_deinit(bp_server_s *server)
{
	if (server->listener) {
		evconnlistener_free(server->listener);
	}
	return 0;
}

int bp_server_listen(bp_server_s *server, unsigned short port)
{
	struct sockaddr_in6 listensin;
	memset(&listensin, 0, sizeof(listensin));
	listensin.sin6_family = AF_INET6;
	listensin.sin6_port = htons(port);
	server->listener = evconnlistener_new_bind(server->program->eventbase, accept_conn_cb, server, LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1, (struct sockaddr*)&listensin, sizeof(listensin));
	if (!server->listener) {
		write_log(5, "Failed to listen on port %u", port);
		return -1;
	}
	
	return 0;
}

static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd,
						   struct sockaddr *address, int socklen, void* ctx)
{
	struct sockaddr_in6 sin;
	struct sockaddr_in6 *sinp;
	if (address->sa_family == AF_INET6) {
		sinp = (struct sockaddr_in6*)address;
	}
	else if (address->sa_family == AF_INET) {
		sin = bp_in4to6((struct sockaddr_in*)address);
		socklen = sizeof(sin);
		sinp = &sin;
	}
	else {
		write_log(4, "Unable to handle incoming connection: unknown address family");
		evutil_closesocket(fd);
		return;
	}
	
	write_log(2, "Incoming connection");
	bp_server_s *server = ctx;
	bp_connection_s *conn = malloc(sizeof(bp_connection_s));
	if (bp_connection_init_socket(conn, server, sinp, socklen, fd) < 0) {
		bp_connection_free(conn);
	}
}