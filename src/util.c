/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#include <assert.h>
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

struct sockaddr_in6 bp_in4to6(struct sockaddr_in *orig)
{
	assert(orig->sin_family == AF_INET);
	struct sockaddr_in6 result;
	memset(&result, 0, sizeof(result));
	
	result.sin6_family = AF_INET6;
	result.sin6_port = orig->sin_port;
	unsigned char *addr = result.sin6_addr.s6_addr;
	addr[10] = addr[11] = 0xFF;
	memcpy(addr+12, &orig->sin_addr, 4);
	
	return result;
}
