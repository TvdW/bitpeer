/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#pragma once
#include <event2/event.h>

struct bp_btcblock_header_t {
	ev_uint32_t version;
	char prevhash[32];
	char merklehash[32];
	ev_uint32_t time;
	ev_uint32_t bits;
	ev_uint32_t nonce;
};
typedef struct bp_btcblock_header_t bp_btcblock_header_s;

