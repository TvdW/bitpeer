#pragma once
#include <event2/event.h>
#include "addrpool.h"
#include "blockstorage.h"
#include "txpool.h"

struct bp_program_t {
	// References to other objects
	struct event_base *eventbase;
	ev_uint32_t network_magic;
	bp_addrpool_s addrpool;
	bp_blockstorage_s blockstorage;
	bp_txpool_s txpool;
	
	void** connections;
	unsigned int cur_connections;
	
	// Settings
	unsigned int addrpool_size;
	unsigned int min_connections;
	unsigned int max_connections;
	
	unsigned short listen_v4;
	unsigned short listen_v6;
	
	unsigned int seed_host4;
	unsigned short seed_port4;
	
	unsigned int my_ip4;
	unsigned short my_ip4port;
	
	unsigned int txpool_size;
	
	unsigned reindex_blocks: 1;
	unsigned relay_transactions: 1;
	unsigned relay_blocks: 1;
};
typedef struct bp_program_t bp_program_s;


int bp_program_init(bp_program_s *program);
void bp_program_deinit(bp_program_s *program);