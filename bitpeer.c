#include <event2/event.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "connection.h"
#include "program.h"

int main(int argc, char** argv)
{
	/* For safety we do these protocol struct assertions */
	assert(sizeof(bp_proto_message_s) == 24);
	assert(sizeof(bp_proto_net_addr_s) == 26);
	assert(sizeof(bp_proto_version_s) == 80);
	
	/* Create the main loop */
	bp_program_s program;
	bp_program_init(&program);
	
	program.eventbase = event_base_new();
	
	/* We need to connect to one initial node in order to seed everything.
	   We will not do this discovery ourselves. */
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	sin.sin_port = htons(8333);
	
	bp_connection_s *seed_connection = malloc(sizeof(bp_connection_s));
	bp_connection_connect(seed_connection, &program, (struct sockaddr*)&sin, sizeof(sin));
	seed_connection->is_seed = 1;
	
	/* Run the loop */
	event_base_loop(program.eventbase, 0);
	
	/* It would appear that our loop ended, so clean up */
	event_base_free(program.eventbase);
	
	return EXIT_SUCCESS;
}
