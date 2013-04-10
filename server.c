#include <string.h>
#include <stdlib.h>
#include "connection.h"
#include "server.h"

static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd,
						   struct sockaddr *address, int socklen, void* ctx);

int bp_server_init(bp_server_s *server, bp_program_s *program, int family, char *address, unsigned short port)
{
	server->program = program;
	
	server->local_port = port;
	if (family == 4) {
		memset(server->local_addr, 0, 10);
		memcpy(server->local_addr + 12, address, 4);
		server->local_addr[10] = (char)0xFF;
		server->local_addr[11] = (char)0xFF;
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

int bp_server_listen(bp_server_s *server, unsigned short port)
{
	// TODO: support ipv6
	struct sockaddr_in listensin;
	memset(&listensin, 0, sizeof(listensin));
	listensin.sin_family = AF_INET;
	listensin.sin_port = htons(port);
	server->listener = evconnlistener_new_bind(server->program->eventbase, accept_conn_cb, server, LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1, (struct sockaddr*)&listensin, sizeof(listensin));
	if (!server->listener) {
		printf("Listen4 failed\n");
		return -1;
	}
	
	return 0;
}

static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd,
						   struct sockaddr *address, int socklen, void* ctx)
{
	printf("Incoming connection\n");
	bp_server_s *server = ctx;
	bp_connection_s *conn = malloc(sizeof(bp_connection_s));
	bp_connection_init_socket(conn, server, address, socklen, fd);
}