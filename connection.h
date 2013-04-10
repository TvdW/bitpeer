#pragma once
#include <sys/socket.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include "program.h"
#include "server.h"

/* Protocol structures */
struct bp_proto_message_t {
	ev_uint32_t magic;
	char command[12];
	ev_uint32_t length;
	ev_uint32_t checksum;
};
typedef struct bp_proto_message_t bp_proto_message_s;

struct bp_proto_version_t {
	ev_int32_t version;
	ev_uint64_t services;
	ev_int64_t timestamp;
	bp_proto_net_addr_s addr_recv;
	bp_proto_net_addr_s addr_from;
	ev_uint64_t nonce;
} __attribute__ ((__packed__));
typedef struct bp_proto_version_t bp_proto_version_s;

struct bp_proto_inv_t {
	ev_uint32_t type;
	char hash[32];
};
typedef struct bp_proto_inv_t bp_proto_inv_s;

/* Connection structure */
struct bp_connection_t {
	struct bufferevent 	*sockbuf;
	bp_server_s *server;
	
	unsigned version_sent: 1;
	unsigned verack_recv:  1;
	unsigned in_message:   1;
	unsigned handsshaken:  1;
	unsigned is_seed:      1;
	
	ev_int32_t peer_version;
	
	bp_proto_message_s current_message;
	
	char remote_addr[16];
	unsigned short remote_port;
	unsigned int connection_id;
};
typedef struct bp_connection_t bp_connection_s;

int bp_connection_connect(bp_connection_s *connection, bp_server_s *server, struct sockaddr *address, int addrlen);
int bp_connection_init_socket(bp_connection_s *connection, bp_server_s *server, struct sockaddr *address, int addrlen, evutil_socket_t fd);
void bp_connection_free(bp_connection_s *connection);

int bp_connection_verifypayload(bp_connection_s* connection);
int bp_connection_readpayload(bp_connection_s *connection, unsigned char **payload);
int bp_connection_sendmessage(bp_connection_s *connection, const char *command, unsigned char *payload, unsigned payload_length);
int bp_connection_skipmessage(bp_connection_s *connection);
int bp_connection_broadcast(bp_connection_s *origin, const char *command, unsigned char *payload, unsigned payload_length);
ev_uint64_t bp_connection_readvarint(bp_connection_s *connection, size_t *position);

#define BP_PROTO_NODE_NETWORK 1
