#include <assert.h>
#include "client.h"

int bp_connection_post_handshake(bp_connection_s *connection)
{
	assert(connection->handsshaken == 0);
	connection->handsshaken = 1;
	
	if (connection->is_seed) {
		bp_connection_sendgetaddr(connection);
	}
	
	return 0;
}