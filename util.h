#pragma once
#include <event2/event.h>

ev_uint64_t bp_readvarint(const unsigned char *buffer, size_t *position, size_t length);
int bp_addrtype(const char *address);
