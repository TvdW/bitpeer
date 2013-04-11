#include "blockverify.h"
#include "util.h"
#include "txverify.h"

int bp_block_verify(bp_btcblock_header_s *header, char *txs, size_t txs_len)
{
	size_t position = 0;
	ev_uint64_t txn_count = bp_readvarint((unsigned char*)txs, &position, txs_len);
	
	if (txn_count == 0) return -1;
	
	for (int i = 0; i < txn_count; i++) {
		char *tx = txs + position;
		size_t length;
		if (bp_tx_verify(tx, txs_len - position, &length) < 0) {
			return -1;
		}
		
		position += length;
	}
	
	if (position != txs_len) return -1;
	
	return 0;
}