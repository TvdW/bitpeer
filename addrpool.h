#pragma once

struct bp_addrpool_addr4_t {
	char address[4];
	unsigned int last_seen;
	unsigned short port;
};
typedef struct bp_addrpool_addr4_t bp_addrpool_addr4_s;


struct bp_addrpool_addr6_t {
	char address[16];
	unsigned int last_seen;
	unsigned short port;
};
typedef struct bp_addrpool_addr6_t bp_addrpool_addr6_s;


struct bp_addrpool_t {
	void *program;
	void *raw_storage;
	bp_addrpool_addr4_s *v4pool;
	bp_addrpool_addr6_s *v6pool;
	int v4pointer;
	int v6pointer;
	int v4size;
	int v6size;
};
typedef struct bp_addrpool_t bp_addrpool_s;


int bp_addrpool_init(bp_addrpool_s *pool, void *program);
void bp_addrpool_deinit(bp_addrpool_s *pool);

int bp_addrpool_add(bp_addrpool_s *pool, int family, char *address, unsigned short port, unsigned int last_seen);
