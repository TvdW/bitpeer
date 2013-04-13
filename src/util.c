/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#include <string.h>
#include "util.h"
#include "log.h"

ev_uint64_t bp_readvarint(const unsigned char *buffer, size_t *position, size_t length)
{
	ev_uint64_t num;
	if (buffer[*position] < 0xfd) {
		num = buffer[*position];
		(*position) += 1;
		return num;
	}
	
	if (buffer[*position] == 0xfd && ((*position)+3 <= length)) {
		num = *(ev_uint16_t*)(buffer+(*position)+1);
		(*position) += 3;
		return num;
	}
	
	if (buffer[*position] == 0xfe && ((*position)+5 <= length)) {
		num = *(ev_uint32_t*)(buffer+(*position)+1);
		(*position) += 5;
		return num;
	}
	
	if (buffer[*position] == 0xff && ((*position)+9 <= length)) {
		num = *(ev_uint64_t*)(buffer+(*position)+1);
		(*position) += 9;
		return num;
	}
	
	write_log(3, "Failed to parse varint");
	
	(*position) += 1;
	return 0;
}

const char v4prefix[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (char)0xFF, (char)0xFF};
int bp_addrtype(const char *address) {
	if (memcmp(address, v4prefix, 12) == 0) {
		return 4;
	}
	
	return 6;
}