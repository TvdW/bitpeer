/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "invvector.h"

bp_invvector_s *bp_invvector_new(size_t maxsize)
{
	bp_invvector_s *vec = malloc(sizeof(bp_invvector_s));
	assert(vec);
	memset(vec, 0, sizeof(bp_invvector_s));
	
	vec->allocsize = maxsize;
	vec->currentindex = 0;
	vec->buffer = malloc(9 + (36 * maxsize));
	assert(vec->buffer);
	
	return vec;
}

void bp_invvector_free(bp_invvector_s *vec)
{
	if (vec->buffer) free(vec->buffer);
	free(vec);
}

int bp_invvector_getbuffer(bp_invvector_s *vec, char **buffer)
{
	size_t sizelen;
	
	// Write the index
	if (vec->currentindex < 0xfd) {
		vec->buffer[8] = vec->currentindex;
		*buffer = vec->buffer + 8;
		sizelen = 1;
	}
	else if (vec->currentindex < 0xffff) {
		vec->buffer[6] = (char)0xfd;
		memcpy(vec->buffer+7, &vec->currentindex, 2);
		*buffer = vec->buffer + 6;
		sizelen = 3;
	}
	else if (vec->currentindex < 0xffffffff) {
		vec->buffer[4] = (char)0xfe;
		memcpy(vec->buffer+5, &vec->currentindex, 4);
		*buffer = vec->buffer + 4;
		sizelen = 5;
	}
	else {
		vec->buffer[0] = (char)0xff;
		memcpy(vec->buffer+1, &vec->currentindex, 8);
		*buffer = vec->buffer;
		sizelen = 9;
	}
	
	return sizelen + (36 * vec->currentindex);
}

int bp_invvector_add(bp_invvector_s *vec, int type, char *hash)
{
	char *loc = (vec->buffer + 9) + (36 * vec->currentindex);
	
	memcpy(loc, &type, 4);
	memcpy(loc+4, hash, 32);
	
	vec->currentindex += 1;
	
	return 0;
}