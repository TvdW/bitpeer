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
	program.addrpool_size = 20480;
	program.min_connections = 8;
	program.max_connections = 4096;
	program.reindex_blocks = 0;
	program.relay_transactions = 1;
	program.relay_blocks = 1;
	program.txpool_size = 1024;
	
	/* Interpret the command line */
	if (argc < 2) {
		printf("Invalid command line arguments.\n");
		printf("Usage:  bitpeer [listen_port] [public_ip] -n [seed_node]\n");
		printf("public_ip and seed_node may optionally contain a port number.\n");
		return EXIT_FAILURE;
	}
	
	unsigned short listen_v4 = atoi(argv[1]);
	if (listen_v4 == 0) {
		printf("Invalid port number specified. Valid ports go from 1 to 65535.\n");
		return EXIT_FAILURE;
	}
	
	struct sockaddr v4_sockaddr;
	struct sockaddr_in *v4_sockaddr_p = (struct sockaddr_in*)&v4_sockaddr;
	int v4_sockaddr_len = sizeof(v4_sockaddr);
	if (evutil_parse_sockaddr_port(argv[2], &v4_sockaddr, &v4_sockaddr_len) < 0) {
		printf("Invalid public_ip specified\n");
		return EXIT_FAILURE;
	}
	if (v4_sockaddr.sa_family != AF_INET) {
		printf("public_ip must be IPv4\n");
		return EXIT_FAILURE;
	}
	if (v4_sockaddr_p->sin_port == 0) {
		v4_sockaddr_p->sin_port = ntohs(listen_v4);
	}
	
	int nodecount = 0;
	struct sockaddr *nodeaddrs = NULL;
	int *nodelens = NULL;
	int *nodeperm = NULL;
	
	/* Now interpret the optional arguments */
	// Quick preprocessor macro to go to the next argv
	
#define NEXT_I() {i++; if (i >= argc) { printf("Argument for %s missing\n", argv[i-1]); return EXIT_FAILURE; }}
	for (int i = 3; i < argc; i++) {
		if (strcmp(argv[i], "--reindex") == 0) {
			program.reindex_blocks = 1;
		}
		else if (strcmp(argv[i], "--addnode") == 0  || strcmp(argv[i], "-n") == 0 ||
				 strcmp(argv[i], "--addpnode") == 0 || strcmp(argv[i], "-p") == 0) {
			NEXT_I();
			nodeaddrs = realloc(nodeaddrs, (nodecount+1) * sizeof(struct sockaddr));
			nodelens = realloc(nodelens, (nodecount+1) * sizeof(int));
			nodeperm = realloc(nodeperm, (nodecount+1) * sizeof(int));
			nodelens[nodecount] = sizeof(struct sockaddr);
			nodeperm[nodecount] = 0;
			
			if (strcmp(argv[i], "--addpnode") == 0 || strcmp(argv[i], "-p") == 0) {
				nodeperm[nodecount] = 1;
			}
			
			struct sockaddr *addr = &nodeaddrs[nodecount];
			memset(addr, 0, sizeof(struct sockaddr));
			
			if (evutil_parse_sockaddr_port(argv[i], addr, nodelens+nodecount) < 0) {
				printf("Invalid node address specified: %s %d\n", argv[i], nodelens[nodecount]);
				return EXIT_FAILURE;
			}
			
			// TODO: port
			
			nodecount += 1;
		}
		else if (strcmp(argv[i], "--txpool") == 0) {
			NEXT_I();
			program.txpool_size = atoi(argv[i]);
			if (program.txpool_size <= 0) {
				printf("Invalid argument for %s\n", argv[i-1]);
				return EXIT_FAILURE;
			}
		}
		else if (strcmp(argv[i], "--addrpool") == 0) {
			NEXT_I();
			program.addrpool_size = atoi(argv[i]);
			if (program.addrpool_size <= 0) {
				printf("Invalid argument for %s\n", argv[i-1]);
				return EXIT_FAILURE;
			}
		}
		else if (strcmp(argv[i], "--no-tx") == 0) {
			program.relay_transactions = 0;
		}
		else if (strcmp(argv[i], "--no-blocks") == 0) {
			program.relay_blocks = 0;
		}
		else if (strcmp(argv[i], "--minconn") == 0) {
			NEXT_I();
			program.min_connections = atoi(argv[i]);
		}
		else if (strcmp(argv[i], "--maxconn") == 0) {
			NEXT_I();
			program.max_connections = atoi(argv[i]);
			if (program.max_connections <= 0) {
				printf("Invalid argument for %s\n", argv[i-1]);
				return EXIT_FAILURE;
			}
		}
		else if (strcmp(argv[i], "--evdebug") == 0) {
			event_enable_debug_logging(EVENT_DBG_ALL);
			event_set_log_callback(log_cb);
			event_enable_debug_mode();
		}
		else {
			printf("Unknown argument '%s'\n", argv[i]);
			return EXIT_FAILURE;
		}
	}
	
	/* Create the main loop */
	bp_program_init(&program);
	
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
	for (int i = 0; i < nodecount; i++) {
		bp_connection_s *seed_connection = malloc(sizeof(bp_connection_s));
		bp_connection_connect(seed_connection, &server, &nodeaddrs[i], nodelens[i]);
		seed_connection->is_seed = 1;
		seed_connection->is_permanent = nodeperm[i];
	}
	
	free(nodeaddrs);
	free(nodelens);
	
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
