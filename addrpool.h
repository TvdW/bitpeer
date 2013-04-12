/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#pragma once
#include <event2/event.h>

struct bp_proto_net_addr_t {
	ev_uint64_t services;
	char address[16];
	ev_uint16_t port;
} __attribute__ ((__packed__));
typedef struct bp_proto_net_addr_t bp_proto_net_addr_s;

struct bp_proto_net_addr_full_t {
	unsigned int time;
	ev_uint64_t services;
	char address[16];
	ev_uint16_t port;
} __attribute__ ((__packed__));
typedef struct bp_proto_net_addr_full_t bp_proto_net_addr_full_s;

struct bp_addrpool_t {
	void *program;
	void *raw_storage;
	unsigned int size;
	unsigned int fillsize;
	unsigned int readpos;
};
typedef struct bp_addrpool_t bp_addrpool_s;


int bp_addrpool_init(bp_addrpool_s *pool, void *program);
void bp_addrpool_deinit(bp_addrpool_s *pool);

int bp_addrpool_add(bp_addrpool_s *pool, bp_proto_net_addr_full_s *entry);
int bp_addrpool_read(bp_addrpool_s *pool, bp_proto_net_addr_full_s **target, int validator(bp_proto_net_addr_full_s *entry, void *ctx), void *ctx);
int bp_addrpool_hasaddr(bp_addrpool_s *pool, bp_proto_net_addr_full_s *addr);
