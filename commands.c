#include <openssl/sha.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include "commands.h"
#include "client.h"
#include "addrpool.h"
#include "util.h"
#include "blockstorage.h"
#include "txpool.h"
#include "txverify.h"
#include "log.h"

// Constants for the network protocol. Ugly but efficient
const ev_int32_t client_version =  70001;
const char version_command[] =     {'v', 'e', 'r', 's', 'i', 'o', 'n', 0,   0,   0,   0,   0  };				// version       [command]
const char verack_command[] =      {'v', 'e', 'r', 'a', 'c', 'k', 0,   0,   0,   0,   0,   0  };				// verack        [command]
const char addr_command[] =        {'a', 'd', 'd', 'r', 0,   0,   0,   0,   0,   0,   0,   0  };				// addr          [command]
const char inv_command[] =         {'i', 'n', 'v', 0,   0,   0,   0,   0,   0,   0,   0,   0  };				// inv           [command]
const char getdata_command[] =     {'g', 'e', 't', 'd', 'a', 't', 'a', 0,   0,   0,   0,   0  };				// getdata       [command]
const char notfound_command[] =    {'n', 'o', 't', 'f', 'o', 'u', 'n', 'd', 0,   0,   0,   0  };				// notfound      [command]
const char getblocks_command[] =   {'g', 'e', 't', 'b', 'l', 'o', 'c', 'k', 's', 0,   0,   0  };				// getblocks     [command]
const char getheaders_command[] =  {'g', 'e', 't', 'h', 'e', 'a', 'd', 'e', 'r', 's', 0,   0  };				// getheaders    [command]
const char tx_command[] =          {'t', 'x', 0,   0,   0,   0,   0,   0,   0,   0,   0,   0  };				// tx            [command]
const char block_command[] =       {'b', 'l', 'o', 'c', 'k', 0,   0,   0,   0,   0,   0,   0  };				// block         [command]
const char headers_command[] =     {'h', 'e', 'a', 'd', 'e', 'r', 's', 0,   0,   0,   0,   0  };				// headers       [command]
const char getaddr_command[] =     {'g', 'e', 't', 'a', 'd', 'd', 'r', 0,   0,   0,   0,   0  };				// getaddr       [command]
const char checkorder_command[] =  {'c', 'h', 'e', 'c', 'k', 'o', 'r', 'd', 'e', 'r', 0,   0  };				// checkorder    [command]
const char submitorder_command[] = {'s', 'u', 'b', 'm', 'i', 't', 'o', 'r', 'd', 'e', 'r', 0  };				// submitorder   [command]
const char ping_command[] =        {'p', 'i', 'n', 'g', 0,   0,   0,   0,   0,   0,   0,   0  };				// ping          [command]
const char pong_command[] =        {'p', 'o', 'n', 'g', 0,   0,   0,   0,   0,   0,   0,   0  };				// pong          [command]
const char reply_command[] =       {'r', 'e', 'p', 'l', 'y', 0,   0,   0,   0,   0,   0,   0  };				// reply         [command]
const char alert_command[] =       {'a', 'l', 'e', 'r', 't', 0,   0,   0,   0,   0,   0,   0  };				// alert         [command]
const char useragent_str[] =       {13,  '/', 'B', 'i', 't', 'p', 'e', 'e', 'r', ':', '0', '.', '1', '/'};		// /Bitpeer:0.1/ [var_str]


int bp_connection_readmessage(bp_connection_s *connection)
{
	if (memcmp(connection->current_message.command, version_command, 12) == 0) {
		return bp_connection_readversion(connection);
	}
	
	if (memcmp(connection->current_message.command, verack_command, 12) == 0) {
		return bp_connection_readverack(connection);
	}
	
	if (memcmp(connection->current_message.command, addr_command, 12) == 0) {
		return bp_connection_readaddr(connection);
	}
	
	if (memcmp(connection->current_message.command, getaddr_command, 12) == 0) {
		return bp_connection_readgetaddr(connection);
	}
	
	if (memcmp(connection->current_message.command, inv_command, 12) == 0) {
		return bp_connection_readinv(connection);
	}
	
	if (memcmp(connection->current_message.command, tx_command, 12) == 0) {
		return bp_connection_readtx(connection);
	}
	
	if (memcmp(connection->current_message.command, getdata_command, 12) == 0) {
		return bp_connection_readgetdata(connection);
	}
	
	write_log(3, "Unknown message type \"%s\"", connection->current_message.command);
	bp_connection_skipmessage(connection);
	
	return -1;
}

/* Version handshake commands */
int bp_connection_sendversion(bp_connection_s *connection)
{
	assert(connection->version_sent == 0);
	connection->version_sent = 1;
	
	unsigned char payload[85 + sizeof(useragent_str)];
	memset(&payload, 0, sizeof(payload));
	bp_proto_version_s *msghead = (bp_proto_version_s*)payload;
	msghead->version = client_version;
	msghead->services = BP_PROTO_NODE_NETWORK;
	msghead->timestamp = (ev_uint64_t)time(0);
	msghead->nonce = 123; // TODO
	memcpy(payload+80, useragent_str, sizeof(useragent_str));
	
	memcpy(msghead->addr_recv.address, connection->remote_addr, 16);
	msghead->addr_recv.port = ntohs(connection->remote_port);
	
	memcpy(msghead->addr_from.address, connection->server->local_addr, 16);
	msghead->addr_from.port = ntohs(connection->server->local_port);
	
	unsigned int start_height = bp_blockstorage_getheight(&connection->server->program->blockstorage);
	memcpy(payload + 80 + sizeof(useragent_str), &start_height, 4);
	
	if (connection->server->program->relay_transactions)
		payload[84 + sizeof(useragent_str)] = 1;
	
	return bp_connection_sendmessage(connection, version_command, payload, 85 + sizeof(useragent_str));
}

int bp_connection_readversion(bp_connection_s *connection)
{
	if (connection->current_message.length > 1024 || connection->current_message.length < 46) {
		bp_connection_skipmessage(connection);
		return -1;
	}
	
	if (connection->peer_version) {
		// This is bad. Can we just skip it?
		bp_connection_skipmessage(connection);
		return -1;
	}
	
	unsigned char *payload;
	if (bp_connection_readpayload(connection, &payload) < 0) {
		return -1;
	}
	
	// TODO: check allowable versions
	bp_proto_version_s *peerversion = (bp_proto_version_s*)payload;
	write_log(2, "Exchanging version messages (incoming), peer version protocol %d", peerversion->version);
	
	if (peerversion->version <= 0) {
		free(payload);
		bp_connection_free(connection); // Disconnect
		return -1;
	}
	
	connection->peer_version = peerversion->version;
	
	free(payload);
	
	int r = bp_connection_sendverack(connection);
	if (r < 0) return r;
	
	if (connection->verack_recv) {
		return bp_connection_post_handshake(connection);
	}
	
	return 0;
}


int bp_connection_sendverack(bp_connection_s *connection)
{
	assert(connection->peer_version != 0);
	return bp_connection_sendmessage(connection, verack_command, NULL, 0);
}

int bp_connection_readverack(bp_connection_s *connection)
{
	if (connection->current_message.length > 1024) {
		bp_connection_skipmessage(connection);
		return -1;
	}
	
	write_log(2, "Peer acknowledged version info");
	unsigned char *payload;
	if (bp_connection_readpayload(connection, &payload) < 0) {
		return -1;
	}
	
	free(payload);
	
	connection->verack_recv = 1;
	if (connection->peer_version) {
		return bp_connection_post_handshake(connection);
	}
	
	return 0;
}


/* address commands */
int bp_connection_sendgetaddr(bp_connection_s *connection)
{
	return bp_connection_sendmessage(connection, getaddr_command, NULL, 0);
}

int bp_connection_readgetaddr(bp_connection_s *connection)
{
	if (connection->current_message.length != 0) {
		bp_connection_skipmessage(connection);
		return -1;
	}
	
	return 0;
}

int bp_connection_readaddr(bp_connection_s *connection)
{
	if (connection->current_message.length > (1000 * 30 + 3)) {
		bp_connection_skipmessage(connection);
		return -1;
	}
	
	unsigned char *payload;
	if (bp_connection_readpayload(connection, &payload) < 0) {
		return -1;
	}
	
	size_t position = 0;
	ev_uint64_t addrcount = bp_readvarint(payload, &position, connection->current_message.length);
	
	if (addrcount * 30 != connection->current_message.length - position) {
		free(payload);
		return -1;
	}
	
	// Iterate over all addresses
	int any_new = 0;
	for (; position < connection->current_message.length; position += 30) {
		bp_proto_net_addr_full_s *entry = (bp_proto_net_addr_full_s*) (payload + position);
		if (!bp_addrpool_hasaddr(&connection->server->program->addrpool, entry)) {
			bp_addrpool_add(&connection->server->program->addrpool, (bp_proto_net_addr_full_s*) (payload + position));
			any_new = 1;
		}
	}
	
	if (any_new) {
		write_log(2, "Broadcasting address information");
		bp_connection_broadcast(connection, addr_command, payload, connection->current_message.length);
	}
	
	free(payload);
	
	bp_program_check_connections(connection->server->program);
	
	return 0;
}


/* inv commands */
int bp_connection_readinv(bp_connection_s *connection)
{
	if (bp_connection_verifypayload(connection) < 0) {
		bp_connection_skipmessage(connection);
		return -1;
	}
	
	size_t remaining_len = connection->current_message.length;
	ev_uint64_t invcnt = bp_connection_readvarint(connection, &remaining_len);
	
	if (remaining_len != invcnt * 36) {
		evbuffer_drain(bufferevent_get_input(connection->sockbuf), remaining_len);
		return -1;
	}
	
	ev_uint64_t i;
	for (i = 0; i < invcnt; i++) {
		bp_proto_inv_s inv_part;
		bufferevent_read(connection->sockbuf, &inv_part, sizeof(inv_part));
		
		if (inv_part.type == 2) { // block
			if (bp_blockstorage_hasblock(&connection->server->program->blockstorage, inv_part.hash) > 0) {
				//printf("We have it though\n");
			}
			else {
				//printf("We don't have it yet\n");
			}
		}
		else if (inv_part.type == 1) { // tx
			if (bp_txpool_gettx(&connection->server->program->txpool, inv_part.hash) != NULL) {
				//printf("We have it though\n");
			}
			else {
				//printf("We don't have it yet\n");
				// TODO: group these
				write_log(2, "Requesting tx info");
				bp_connection_sendgetdata(connection, 1, inv_part.hash);
			}
		}
	}
	
	return 0;
}

int bp_connection_readtx(bp_connection_s *connection)
{
	unsigned char *payload;
	if (bp_connection_readpayload(connection, &payload) < 0) {
		return -1;
	}
	
	if (bp_tx_verify((char*)payload, connection->current_message.length) < 0) {
		write_log(2, "Invalid tx received");
		free(payload);
		return -1;
	}
	
	// TODO: we're doing this twice.
	unsigned char hash1[SHA256_DIGEST_LENGTH];
	unsigned char hash2[SHA256_DIGEST_LENGTH];
	SHA256(payload, connection->current_message.length, hash1);
	SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
	
	// We don't have to free the pointer, as the txpool takes it from us
	bp_txpool_addtx(&connection->server->program->txpool, (char*)payload, connection->current_message.length);
	
	write_log(2, "New tx stored in the pool");
	
	// Announce it
	unsigned char announcement[37];
	announcement[0] = announcement[1] = 1;
	announcement[2] = announcement[3] = announcement[4] = 0;
	memcpy(announcement+5, hash2, 32);
	
	return bp_connection_broadcast(connection, inv_command, announcement, 37);
}

int bp_connection_readgetdata(bp_connection_s *connection)
{
	if (bp_connection_verifypayload(connection) < 0) {
		bp_connection_skipmessage(connection);
		return -1;
	}
	
	size_t remaining_len = connection->current_message.length;
	ev_uint64_t getdatacnt = bp_connection_readvarint(connection, &remaining_len);
	
	if (remaining_len != getdatacnt * 36) {
		evbuffer_drain(bufferevent_get_input(connection->sockbuf), remaining_len);
		return -1;
	}
	
	ev_uint64_t i;
	for (i = 0; i < getdatacnt; i++) {
		bp_proto_inv_s inv_part;
		bufferevent_read(connection->sockbuf, &inv_part, sizeof(inv_part));
		
		if (inv_part.type == 1) { // tx
			bp_txpool_tx_s *tx = bp_txpool_gettx(&connection->server->program->txpool, inv_part.hash);
			if (!tx) {
				// Not found. // TODO: group these
				// TODO: notfound
				write_log(2, "Peer requested unknown tx block");
				continue;
			}
			
			// TODO: we already have the checksum...
			write_log(2, "Sending a tx block to peer");
			bp_connection_sendmessage(connection, tx_command, (unsigned char*)tx->data, tx->length);
		}
	}
	
	return 0;
}

int bp_connection_sendgetdata(bp_connection_s *connection, int type, char *hash)
{
	unsigned char sendblock[37];
	memcpy(sendblock+5, hash, 32);
	sendblock[0] = 1;
	sendblock[1] = type;
	sendblock[2] = sendblock[3] = sendblock[4] = 0;
	
	return bp_connection_sendmessage(connection, getdata_command, sendblock, 37);
}







