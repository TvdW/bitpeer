#include <event2/event.h>
#include <event2/listener.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "connection.h"
#include "program.h"
#include "server.h"

void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd,
					struct sockaddr *address, int socklen, void* ctx)
{
	printf("Incoming connection\n");
	bp_server_s *server = ctx;
	bp_connection_s *conn = malloc(sizeof(bp_connection_s));
	bp_connection_init_socket(conn, server, fd);
}

int main(int argc, char** argv)
{
	/* For safety we do these protocol struct assertions */
	assert(sizeof(bp_proto_message_s) == 24);
	assert(sizeof(bp_proto_net_addr_s) == 26);
	assert(sizeof(bp_proto_version_s) == 80);
	
	/* Set the settings */
	bp_program_s program;
	program.addrpool_v4count = 4096;
	program.addrpool_v6count = 128;
	program.min_connections  = 10;
	program.listen_v4 = 8334;
	program.listen_v6 = 0;
	program.seed_host4 = 0x7f000001;
	program.seed_port4 = 8333;
	
	program.my_ip4 = htonl(0x54544411);
	program.my_ip4port = 8333;
	
	/* Create the main loop */
	bp_program_init(&program);
	
	program.eventbase = event_base_new();
	
	/* Create a server */
	bp_server_s server;
	bp_server_init(&server, &program, 4, (char*)&program.my_ip4, program.my_ip4port);
	
	/* We need to connect to one initial node in order to seed everything.
	   We will not do this initial discovery ourselves. */
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(program.seed_host4);
	sin.sin_port = htons(program.seed_port4);
	
	bp_connection_s *seed_connection = malloc(sizeof(bp_connection_s));
	bp_connection_connect(seed_connection, &server, (struct sockaddr*)&sin, sizeof(sin));
	seed_connection->is_seed = 1;
	
	/* We'll also need to listen for incoming connections */
	/*if (program.listen_v4) {
		struct sockaddr_in listensin;
		memset(&listensin, 0, sizeof(listensin));
		listensin.sin_family = AF_INET;
		listensin.sin_port = htons(program.listen_v4);
		struct evconnlistener *listener = evconnlistener_new_bind(program.eventbase, accept_conn_cb, &program, LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1, (struct sockaddr*)&listensin, sizeof(listensin));
		if (!listener) {
			printf("Listen4 failed\n");
			return EXIT_FAILURE;
		}
	}*/
	
	/* Run the loop */
	event_base_loop(program.eventbase, 0);
	
	/* It would appear that our loop ended, so clean up */
	event_base_free(program.eventbase);
	bp_program_deinit(&program);
	
	return EXIT_SUCCESS;
}
