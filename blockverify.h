#pragma once
#include "btcblock.h"

int bp_block_verify(bp_btcblock_header_s *header, char *txs, size_t txs_len);