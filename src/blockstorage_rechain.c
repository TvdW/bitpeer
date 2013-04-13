#include <assert.h>
#include <string.h>
#include "blockstorage.h"
#include "log.h"

int bp_blockstorage_rechain_main(bp_blockstorage_s *storage)
{
	// This gets called when we just had a new block stored on top.
	// Check whether we have any orphans that should actually be in the main chain
	// This can happen when we simply receive blocks in the wrong order
	while (1) {
		char *top_of_chain = bp_blockstorage_gettop(storage);
		if (!top_of_chain) {
			// This can only mean that we've never had the genesis block
			// And since that block can't be an orphan, there's nothing we can do here.
			return 0;
		}
		
		int found_anything = 0;
		for (int i = 0; i < storage->orphans_writepos; i += 80) {
			char *orphan = storage->orphans + i;
			if (memcmp(orphan+32, top_of_chain, 32) == 0) {
				// Found a new top block
				char block[80];
				memcpy(block, orphan, 80);
				
				// Delete it from the index, then add it again
				bp_blockstorage_deindex(storage, 1, i/80);
				bp_blockstorage_index(storage, block, block+32, *(unsigned int*)(block+64), *(unsigned int*)(block+68), *(unsigned int*)(block+72), *(unsigned int*)(block+76));
				
				write_log(2, "Moved a block from orphan to main");
				found_anything = 1;
				break;
			}
		}
		
		if (found_anything == 0)
			break;
	}
	
	// Since we may have destoyed our cache, we better build it again
	// TODO: only rehahs the orphan cache
	if (storage->orphanindex == NULL) bp_blockstorage_rehash(storage);
	return 0;
}

int bp_blockstorage_rechain_orphan(bp_blockstorage_s *storage)
{
	// TODO
	return 0;
}

int bp_blockstorage_deindex(bp_blockstorage_s *storage, int chain, int num)
{
	assert(chain == 1); // Only chain we support atm
	
	if (chain == 1) {
		// Destroy our index, as we can't just remove this one row // TODO
		if (storage->orphanindex) bp_blockstorage_hashmap_free(storage->orphanindex);
		storage->orphanindex = NULL;
		
		int blocks_in_chain = storage->orphans_writepos / 80;
		if (num < blocks_in_chain-1) { // Not the last block
			char *oldblock = storage->orphans + (80 * num);
			char *newblock = storage->orphans + storage->orphans_writepos - 80;
			
			// Copy the block
			memcpy(oldblock, newblock, 80);
		}
		storage->orphans_writepos -= 80;
		
		// Write the new orphans file
		if (storage->orphans_fd) {
			fclose(storage->orphans_fd);
			storage->orphans_fd = fopen("orphans.dat", "wb");
			assert(storage->orphans_fd);
			int r = fwrite(storage->orphans, storage->orphans_writepos, 1, storage->orphans_fd);
			assert(r == 1);
			fflush(storage->orphans_fd);
		}
		
		return 0;
	}
	else {
		return -1;
	}
}
