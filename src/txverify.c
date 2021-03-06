/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#include <event2/event.h>
#include "txverify.h"
#include "util.h"

int bp_tx_verify(char *tx, size_t tx_len, size_t *store_length)
{
	if (tx_len < 60) return -1;
	
	int version = *(unsigned int*)tx;
	(void)(version);
	size_t position = 4;
	
	ev_uint64_t tx_in_c = bp_readvarint((unsigned char*)tx, &position, tx_len);
	if (tx_in_c == 0) return -1;
	
	for (int i = 0; i < tx_in_c; i++) {
		if (tx_len - position < 37) return -1;
		
		char *hash = tx + position;
		ev_uint32_t index = *(ev_uint32_t*)(tx + position + 32);
		position += 36;
		
		ev_uint64_t script_len = bp_readvarint((unsigned char*)tx, &position, tx_len);
		if (tx_len - position < script_len + 4) return -1;
		// TODO: check script
		if (script_len > 10000) return -1;
		
		position += script_len;
		
		ev_uint32_t seq = *(ev_uint32_t*)(tx + position);
		position += 4;
		
		(void)(seq);
		(void)(index);
		(void)(hash);
	}
	
	ev_uint64_t tx_out_c = bp_readvarint((unsigned char*)tx, &position, tx_len);
	if (tx_out_c == 0) return -1;
	
	for (int i = 0; i < tx_out_c; i++) {
		if (tx_len - position < 9) return -1;
		
		ev_uint64_t value = *(ev_uint64_t*)(tx + position);
		position += 8;
		ev_uint64_t script_len = bp_readvarint((unsigned char*)tx, &position, tx_len);
		
		position += script_len;
		
		(void)(value);
	}
	
	position += 4;
	
	if (!store_length) {
		if (tx_len - position != 0) return -1; // data not finished
	}
	else {
		*store_length = position;
	}
	
	return 0;
}