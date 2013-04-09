#include <assert.h>
#include <string.h>
#include <openssl/sha.h>
#include <event2/buffer.h>
#include <stdlib.h>
#include "connection.h"
#include "commands.h"

int bp_connection_init(bp_connection_s *connection, bp_server_s *server);
int bp_connection_init_finish(bp_connection_s *connection);

void bp_connection_readcb (struct bufferevent *bev, void *ctx);
void bp_connection_writecb(struct bufferevent *bev, void *ctx);
void bp_connection_eventcb(struct bufferevent *bev, short events, void *ctx);

/* Initialization */
int bp_connection_init(bp_connection_s *connection, bp_server_s *server)
{
	// TODO: we really need remote_addr set
	memset(connection, 0, sizeof(bp_connection_s));
	connection->remote_addr[11] = connection->remote_addr[10] = 0xFF;
	connection->server = server;
	return 0;
}

int bp_connection_init_finish(bp_connection_s *connection)
{
	/* Set the event callbacks */
	bufferevent_setcb(connection->sockbuf, bp_connection_readcb, bp_connection_writecb, bp_connection_eventcb, connection);
	
	bufferevent_enable(connection->sockbuf, EV_READ|EV_WRITE);
	
	/* Do the handshake dance */
	bp_connection_sendversion(connection);
	
	return 0;
}

int bp_connection_init_socket(bp_connection_s *connection, bp_server_s *server, evutil_socket_t fd)
{
	int r = bp_connection_init(connection, server);
	if (r < 0) {
		return r;
	}
	
	connection->sockbuf = bufferevent_socket_new(server->program->eventbase, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!connection->sockbuf) {
		return -1;
	}
	
	return bp_connection_init_finish(connection);
}

int bp_connection_connect(bp_connection_s *connection, bp_server_s *server, struct sockaddr *address, int addrlen)
{
	int r = bp_connection_init(connection, server);
	if (r < 0) {
		return r;
	}
	
	connection->sockbuf = bufferevent_socket_new(server->program->eventbase, -1, BEV_OPT_CLOSE_ON_FREE);
	if (!connection->sockbuf) return -1;
	
	if (bufferevent_socket_connect(connection->sockbuf, address, addrlen) < 0) {
		bufferevent_free(connection->sockbuf);
		return -1;
	}
	
	return bp_connection_init_finish(connection);
}


void bp_connection_free(bp_connection_s *connection)
{
	bufferevent_free(connection->sockbuf);
	free(connection);
}


/* Events */
void bp_connection_readcb(struct bufferevent *bev, void *ctx)
{
	bp_connection_s *connection = (bp_connection_s*)ctx;
	struct evbuffer *input = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(input);
	printf("Read callback (%li)\n", len);
	
begin:
	if (connection->in_message == 0) {
		if (len < 24) {
			return;
		}
		
		int r = bufferevent_read(connection->sockbuf, &connection->current_message, 24);
		assert(r == 24);
		connection->in_message = 1;
		len -= 24;
	}
	
	if (connection->in_message == 1) {
		if (len < connection->current_message.length) {
			return;
		}
		
		if (connection->current_message.magic != connection->server->program->network_magic) {
			bp_connection_skipmessage(connection);
		}
		else {
			bp_connection_readmessage(connection);
		}
		
		connection->in_message = 0;
		len -= connection->current_message.length;
	}
	
	assert(evbuffer_get_length(input) == len);
	
	goto begin;
}

void bp_connection_writecb(struct bufferevent *bev, void *ctx)
{
	//bp_connection_s *connection = (bp_connection_s*)ctx;
	printf("Write callback\n");
}

void bp_connection_eventcb(struct bufferevent *bev, short events, void *ctx)
{
	bp_connection_s *connection = (bp_connection_s*)ctx;
	printf("Event %d callback\n", events);
	
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bp_connection_free(connection);
	}
}



/* Protocol send functions */
int bp_connection_sendmessage(bp_connection_s *connection, const char *command, unsigned char *payload, unsigned payload_length)
{
	bp_proto_message_s header;
	header.magic = connection->server->program->network_magic;
	memcpy(header.command, command, 12);
	header.length = payload_length;
	
	unsigned char shabuf1[SHA256_DIGEST_LENGTH];
	unsigned char shabuf2[SHA256_DIGEST_LENGTH];
	SHA256(payload, payload_length, shabuf1);
	SHA256(shabuf1, SHA256_DIGEST_LENGTH, shabuf2);
	header.checksum = *(ev_uint32_t*)(shabuf2);
	
	bufferevent_write(connection->sockbuf, &header, sizeof(header));
	if (payload_length)
		bufferevent_write(connection->sockbuf, payload, payload_length);
	
	return 0;
}



/* Protocol recv functions */
int bp_connection_readpayload(bp_connection_s *connection, unsigned char **payload)
{
	if (connection->current_message.length) {
		*payload = malloc(connection->current_message.length);
		int r = bufferevent_read(connection->sockbuf, *payload, connection->current_message.length);
		assert(r == connection->current_message.length);
	}
	else {
		*payload = NULL;
	}
	
	/* Checksum */
	unsigned char shabuf1[SHA256_DIGEST_LENGTH];
	unsigned char shabuf2[SHA256_DIGEST_LENGTH];
	SHA256(*payload, connection->current_message.length, shabuf1);
	SHA256(shabuf1, SHA256_DIGEST_LENGTH, shabuf2);
	ev_uint32_t checksum = *(ev_uint32_t*)(shabuf2);
	
	if (connection->current_message.checksum != checksum) {
		free(*payload);
		*payload = NULL;
		return -1;
	}
	
	return 0;
}

int bp_connection_skipmessage(bp_connection_s *connection)
{
	evbuffer_drain(bufferevent_get_input(connection->sockbuf), connection->current_message.length);
	return 0;
}
