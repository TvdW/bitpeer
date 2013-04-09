#include <event2/event.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "connection.h"
#include "program.h"
#include "server.h"
#include "btcblock.h"

int main(int argc, char** argv)
{
	/* For safety we do these protocol struct assertions */
	assert(sizeof(bp_proto_message_s) == 24);
	assert(sizeof(bp_proto_net_addr_s) == 26);
	assert(sizeof(bp_proto_net_addr_full_s) == 30);
	assert(sizeof(bp_proto_version_s) == 80);
	assert(sizeof(bp_btcblock_header_s) == 80);
	
	/* Set the settings */
	bp_program_s program;
	program.addrpool_size = 4096;
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
	if (bp_server_listen(&server, program.listen_v4) < 0) {
		return EXIT_FAILURE;
	}
	
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
	
	/* Run the loop */
	event_base_loop(program.eventbase, 0);
	
	/* It would appear that our loop ended, so clean up */
	event_base_free(program.eventbase);
	bp_program_deinit(&program);
	
	return EXIT_SUCCESS;
}
