/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#pragma once
#include <stdlib.h>

struct bp_invvector_t {
	size_t allocsize;
	size_t currentindex;
	char *buffer;
};
typedef struct bp_invvector_t bp_invvector_s;

bp_invvector_s *bp_invvector_new(size_t maxsize);
void bp_invvector_free(bp_invvector_s *vec);

int bp_invvector_getbuffer(bp_invvector_s *vec, char **buffer);
int bp_invvector_add(bp_invvector_s *vec, int type, char *hash);