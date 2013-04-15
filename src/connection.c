/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#include <limits.h>
#include <assert.h>
#include <string.h>
#include <openssl/sha.h>
#include <event2/buffer.h>
#include <stdlib.h>
#include "connection.h"
#include "commands.h"
#include "log.h"
#include "util.h"

int bp_connection_init(bp_connection_s *connection, bp_server_s *server);
int bp_connection_init_finish(bp_connection_s *connection, struct sockaddr *address, int addrlen);

void bp_connection_readcb (struct bufferevent *bev, void *ctx);
void bp_connection_eventcb(struct bufferevent *bev, short events, void *ctx);

/* Initialization */
int bp_connection_init(bp_connection_s *connection, bp_server_s *server)
{
	memset(connection, 0, sizeof(bp_connection_s));
	connection->remote_addr[11] = connection->remote_addr[10] = (char)0xFF;
	connection->server = server;
	connection->connection_id = INT_MAX;
	
	if (server->program->cur_connections == server->program->max_connections) {
		write_log(4, "Rejecting incoming connection because we are at our limit");
		return -1;
	}
	
	int i, found = 0;
	for (i = 0; i < server->program->max_connections; i++) {
		if (server->program->connections[i] == NULL) {
			found = 1;
			connection->connection_id = i;
			server->program->connections[i] = connection;
			server->program->cur_connections += 1;
			break;
		}
	}
	assert(found);
	
	return 0;
}

int bp_connection_init_finish(bp_connection_s *connection, struct sockaddr *address, int addrlen)
{
	/* Set the address */
	if (address->sa_family == AF_INET) {
		connection->remote_addr[10] = connection->remote_addr[11] = (char)0xFF;
		struct sockaddr_in *addr = (struct sockaddr_in*)address;
		memcpy(connection->remote_addr + 12, &addr->sin_addr, 4);
		connection->remote_port = ntohs(addr->sin_port);
	}
	else {
		struct sockaddr_in6 *addr = (struct sockaddr_in6*)address;
		memcpy(connection->remote_addr, &addr->sin6_addr, 16);
		connection->remote_port = ntohs(addr->sin6_port);
	}
	
	
	/* Set the event callbacks */
	bufferevent_setcb(connection->sockbuf, bp_connection_readcb, NULL, bp_connection_eventcb, connection);
	
	struct timeval timeout;
	timeout.tv_sec = 120;
	timeout.tv_usec = 0;
	bufferevent_enable(connection->sockbuf, EV_READ|EV_WRITE);
	bufferevent_set_timeouts(connection->sockbuf, &timeout, &timeout);
	
	/* Do the handshake dance */
	bp_connection_sendversion(connection);
	
	return 0;
}

int bp_connection_init_socket(bp_connection_s *connection, bp_server_s *server, struct sockaddr *address, int addrlen, evutil_socket_t fd)
{
	int r = bp_connection_init(connection, server);
	if (r < 0) {
		evutil_closesocket(fd);
		return r;
	}
	
	connection->sockbuf = bufferevent_socket_new(server->program->eventbase, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!connection->sockbuf) {
		return -1;
	}
	
	return bp_connection_init_finish(connection, address, addrlen);
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
		connection->sockbuf = NULL;
		return -1;
	}
	
	return bp_connection_init_finish(connection, address, addrlen);
}


void bp_connection_free(bp_connection_s *connection)
{
	bp_program_s *program = connection->server->program;
	
	if (connection->connection_id != INT_MAX) {
		assert(program->connections[connection->connection_id] == connection);
		program->connections[connection->connection_id] = NULL;
		program->cur_connections -= 1;
	}
	
	if (connection->sockbuf) bufferevent_free(connection->sockbuf);
	free(connection);
}


/* Events */
void bp_connection_readcb(struct bufferevent *bev, void *ctx)
{
	bp_connection_s *connection = (bp_connection_s*)ctx;
	assert(connection->sockbuf == bev);
	struct evbuffer *input = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(input);
	write_log(0, "Received %u bytes", len);
	
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

void bp_connection_eventcb(struct bufferevent *bev, short events, void *ctx)
{
	bp_connection_s *connection = (bp_connection_s*)ctx;
	bp_program_s *program = connection->server->program;
	
	assert(connection->sockbuf == bev);
	write_log(0, "Received an event (%d)", events);
	
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR) || events & BEV_EVENT_TIMEOUT) {
		if (connection->is_permanent) {
			// TODO: delay connection ~5s
			write_log(2, "Reconnecting to permanent node");
			char remote_addr[16];
			memcpy(remote_addr, connection->remote_addr, 16);
			unsigned short remote_port = connection->remote_port;
			unsigned int is_seed = connection->is_seed;
			bp_server_s *server = connection->server;
			
			bp_connection_free(connection);
			
			int r;
			connection = malloc(sizeof(bp_connection_s));
			if (bp_addrtype(remote_addr) == 4) {
				struct sockaddr_in sin;
				memset(&sin, 0, sizeof(sin));
				sin.sin_family = AF_INET;
				sin.sin_port = ntohs(remote_port);
				memcpy(&sin.sin_addr, remote_addr+12, 4);
				r = bp_connection_connect(connection, server, (struct sockaddr*)&sin, sizeof(sin));
			}
			else {
				struct sockaddr_in6 sin;
				memset(&sin, 0, sizeof(sin));
				sin.sin6_family = AF_INET6;
				sin.sin6_port = ntohs(remote_port);
				memcpy(&sin.sin6_addr, remote_addr, 16);
				r = bp_connection_connect(connection, server, (struct sockaddr*)&sin, sizeof(sin));
			}
			assert(r == 0); // This shouldn't fail...
			connection->is_seed = is_seed;
			connection->is_permanent = 1;
		}
		else {
			bp_connection_free(connection);
			bp_program_check_connections(program);
		}
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

int bp_connection_broadcast(bp_connection_s *origin, const char *command, unsigned char *payload, unsigned payload_length)
{
	bp_proto_message_s header;
	header.magic = origin->server->program->network_magic;
	memcpy(header.command, command, 12);
	header.length = payload_length;
	
	unsigned char shabuf1[SHA256_DIGEST_LENGTH];
	unsigned char shabuf2[SHA256_DIGEST_LENGTH];
	SHA256(payload, payload_length, shabuf1);
	SHA256(shabuf1, SHA256_DIGEST_LENGTH, shabuf2);
	header.checksum = *(ev_uint32_t*)(shabuf2);
	
	int i;
	for (i = 0; i < origin->server->program->max_connections; i++) {
		bp_connection_s *conn = origin->server->program->connections[i];
		if (conn == NULL || conn == origin) continue;
		if (!conn->handsshaken) continue;
		assert(conn->version_sent && conn->verack_recv);
		
		bufferevent_write(conn->sockbuf, &header, sizeof(header));
		if (payload_length)
			bufferevent_write(conn->sockbuf, payload, payload_length);
	}
	
	return 0;
}

int bp_connection_sendfile(bp_connection_s *connection, const char *command, struct evbuffer_file_segment *segment, unsigned int offset, unsigned int size, unsigned int checksum)
{
	bp_proto_message_s header;
	header.magic = connection->server->program->network_magic;
	memcpy(header.command, command, 12);
	header.length = size;
	header.checksum = checksum;
	
	bufferevent_write(connection->sockbuf, &header, sizeof(header));
	
	if (evbuffer_add_file_segment(bufferevent_get_output(connection->sockbuf), segment, offset, size) < 0) {
		write_log(4, "Failed to sendfile()");
		return -1;
	}
	
	return 0;
}


/* Protocol recv functions */
ev_uint64_t bp_connection_readvarint(bp_connection_s *connection, size_t *len)
{
	unsigned char buf[8];
	bufferevent_read(connection->sockbuf, buf, 1);
	if (buf[0] < 0xfd) {
		(*len) -= 1;
		return buf[0];
	}
	if (buf[0] == 0xfd && *len >= 3) {
		bufferevent_read(connection->sockbuf, buf, 2);
		(*len) -= 3;
		return *(ev_uint16_t*)(buf);
	}
	if (buf[0] == 0xfe && *len >= 5) {
		bufferevent_read(connection->sockbuf, buf, 4);
		(*len) -= 5;
		return *(ev_uint32_t*)(buf);
	}
	if (buf[0] == 0xff && *len >= 9) {
		bufferevent_read(connection->sockbuf, buf, 8);
		(*len) -= 9;
		return *(ev_uint64_t*)(buf);
	}
	(*len) -= 1;
	return 0;
}

int bp_connection_readpayload(bp_connection_s *connection, unsigned char **payload)
{
	if (connection->current_message.length) {
		*payload = malloc(connection->current_message.length);
		int r = bufferevent_read(connection->sockbuf, *payload, connection->current_message.length);
		assert(r == connection->current_message.length);
	}
	else {
		return -1;
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

/* Verifies a payload without loading it */
int bp_connection_verifypayload(bp_connection_s* connection)
{
	struct evbuffer *input = bufferevent_get_input(connection->sockbuf);
	struct evbuffer_iovec *v;
	int n = evbuffer_peek(input, connection->current_message.length, NULL, NULL, 0);
	v = malloc(sizeof(struct evbuffer_iovec) * n);
	evbuffer_peek(input, -1, NULL, v, n);
	
	unsigned char hash1[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	
	int i;
	int left = connection->current_message.length;
	for (i = 0; i < n; i++) {
		int len = v[i].iov_len;
		if (len > left) len = left;
		SHA256_Update(&ctx, v[i].iov_base, len);
		
		left -= len;
	}
	
	SHA256_Final(hash1, &ctx);
	free(v);
	
	unsigned char hash2[SHA256_DIGEST_LENGTH];
	SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
	
	ev_uint32_t checksum = *(ev_uint32_t*)(hash2);
	
	if (connection->current_message.checksum != checksum) {
		return -1;
	}
	
	return 0;
}

int bp_connection_skipmessage(bp_connection_s *connection)
{
	evbuffer_drain(bufferevent_get_input(connection->sockbuf), connection->current_message.length);
	return 0;
}
