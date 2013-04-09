#pragma once
#include <event2/event.h>

struct bp_program_t {
	struct event_base *eventbase;
	ev_uint32_t network_magic;
};
typedef struct bp_program_t bp_program_s;


int bp_program_init(bp_program_s *program);