/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#include <event2/event.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>

#include "connection.h"
#include "program.h"
#include "server.h"
#include "btcblock.h"

static void signal_cb(int fd, short event, void *arg)
{
	printf("Caught SIGINT. Will stop in 2 seconds\n");
	bp_program_s *program = arg;
	struct timeval timeout;
	timeout.tv_sec = 2; timeout.tv_usec = 0;
	event_base_loopexit(program->eventbase, &timeout);
}

static void log_cb(int severity, const char *msg)
{
	printf("%s\n", msg);
}

int main(int argc, char** argv)
{
	/* Set the CWD */
	char *home = getenv("HOME");
	if (!home) {
		printf("Failed to load data directory\n");
		return EXIT_FAILURE;
	}
	
	char *datadir = malloc(strlen(home) + 10);
	snprintf(datadir, strlen(home) + 10, "%s/.bitpeer", home);
	
	if (chdir(datadir) < 0) {
		if (mkdir(datadir, 0777) < 0) {
			printf("Failed to create data directory.\n");
			return EXIT_FAILURE;
		}
		
		if (chdir(datadir) < 0) {
			printf("Failed to chdir\n");
			return EXIT_FAILURE;
		}
	}
	
	free(datadir);
	
	/* For safety we do these protocol struct assertions */
	assert(sizeof(bp_proto_message_s) == 24);
	assert(sizeof(bp_proto_net_addr_s) == 26);
	assert(sizeof(bp_proto_net_addr_full_s) == 30);
	assert(sizeof(bp_proto_version_s) == 80);
	assert(sizeof(bp_proto_inv_s) == 36);
	assert(sizeof(bp_btcblock_header_s) == 80);
	
	/* Set the settings */
	bp_program_s program;
	memset(&program, 0, sizeof(program));
	program.addrpool_size = 10240;
	program.min_connections = 32;
	program.max_connections = 4096;
	//program.reindex_blocks = 1;
	program.relay_transactions = 1;
	program.relay_blocks = 0;
	program.txpool_size = 1024;
	
	/* Interpret the command line */
	if (argc < 4) {
		printf("Invalid command line arguments.\n");
		printf("Syntax:     bitpeer [listen_port] [local_addr:port] [seed_addr:port]\n");
		return EXIT_FAILURE;
	}
	
	unsigned short listen_v4 = atoi(argv[1]);
	if (listen_v4 == 0) {
		printf("Invalid port specified\n");
		return EXIT_FAILURE;
	}
	
	struct sockaddr v4_sockaddr;
	int v4_sockaddr_len = sizeof(v4_sockaddr);
	if (evutil_parse_sockaddr_port(argv[2], &v4_sockaddr, &v4_sockaddr_len) < 0) {
		printf("Invalid local_addr specified\n");
		return EXIT_FAILURE;
	}
	if (v4_sockaddr.sa_family != AF_INET) {
		printf("local_addr must be IPv4\n");
		return EXIT_FAILURE;
	}
	struct sockaddr_in *v4_sockaddr_p = (struct sockaddr_in*)&v4_sockaddr;
	if (v4_sockaddr_p->sin_port == 0) {
		
		printf("No local_addr port specified\n");
		return EXIT_FAILURE;
	}
	
	struct sockaddr seed_sockaddr;
	int seed_sockaddr_len = sizeof(seed_sockaddr);
	if (evutil_parse_sockaddr_port(argv[3], &seed_sockaddr, &seed_sockaddr_len) < 0) {
		printf("Invalid seed_addr specified\n");
		return EXIT_FAILURE;
	}
	
	if (argc >= 5) {
		program.min_connections = atoi(argv[4]);
	}
	
	/* Create the main loop */
	bp_program_init(&program);
	
	event_set_log_callback(log_cb);
	event_enable_debug_mode();
	program.eventbase = event_base_new();

	/* Set up the signal handler */
	struct event *signal_event = evsignal_new(program.eventbase, SIGINT, signal_cb, &program);
	evsignal_add(signal_event, NULL);
	
	/* Create a server */
	bp_server_s server;
	program.server_v4 = &server;
	bp_server_init(&server, &program, 4, (char*)&v4_sockaddr_p->sin_addr, v4_sockaddr_p->sin_port);
	if (bp_server_listen(&server, listen_v4) < 0) {
		return EXIT_FAILURE;
	}
	
	/* We need to connect to one initial node in order to seed everything.
	   We will not do this initial discovery ourselves. */
	bp_connection_s *seed_connection = malloc(sizeof(bp_connection_s));
	bp_connection_connect(seed_connection, &server, &seed_sockaddr, seed_sockaddr_len);
	seed_connection->is_seed = 1;
	
	/* Run the loop */
	event_base_loop(program.eventbase, 0);
	printf("Entering clean shutdown state\n");

	/* It would appear that our loop ended, so clean up */
	event_free(signal_event);
	bp_server_deinit(&server);
	
	bp_program_deinit(&program);
	event_base_free(program.eventbase);
	
	return EXIT_SUCCESS;
}
