#include <openssl/sha.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "blockstorage.h"
#include "program.h"
#include "log.h"

const unsigned char genesis[] = {
	0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
	0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
	0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
	0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00};

int bp_blockstorage_init(bp_blockstorage_s *storage, void *_program)
{
	bp_program_s *program = _program;
	
	memset(storage, 0, sizeof(bp_blockstorage_s));
	storage->program = _program;
	
	int do_reindex = 0;
	if (program->reindex_blocks) do_reindex = 1;
	
	// Load mainchain.dat
	if (!do_reindex) {
		FILE *mainchain = fopen("mainchain.dat", "rb");
		if (mainchain) {
			fseek(mainchain, 0, SEEK_END);
			storage->mainchain_writepos = ftell(mainchain);
			fseek(mainchain, 0, SEEK_SET);
			storage->mainchain_allocsize = storage->mainchain_writepos + (48 * 1000);
			storage->mainchain = malloc(storage->mainchain_allocsize);
			int r = fread(storage->mainchain, storage->mainchain_writepos, 1, mainchain);
			fclose(mainchain);

			storage->mainchain_fd = fopen("mainchain.dat", "ab");
			
			if (r != 1 || !storage->mainchain_fd) {
				write_log(4, "Failed to load cached blockchain from mainchain.dat");
				do_reindex = 1;
				free(storage->mainchain);
				storage->mainchain = NULL;
				storage->mainchain_writepos = 0;
				storage->mainchain_allocsize = 0;
			}
		}
	}
	
	// Load orphans.dat
	if (!do_reindex) {
		FILE *orphans = fopen("orphans.dat", "rb");
		if (orphans) {
			fseek(orphans, 0, SEEK_END);
			storage->orphans_writepos = ftell(orphans);
			fseek(orphans, 0, SEEK_SET);
			storage->orphans_allocsize = storage->orphans_writepos + (80 * 500);
			storage->orphans = malloc(storage->orphans_allocsize);
			int r = fread(storage->orphans, storage->orphans_writepos, 1, orphans);
			fclose(orphans);
			
			storage->orphans_fd = fopen("orphans.dat", "ab");
			
			if ((r != 1 && storage->orphans_writepos != 0) || !storage->orphans_fd) {
				write_log(4, "Failed to load cached orphan chain from orphans.dat");
				do_reindex = 1;
				free(storage->orphans);
				storage->orphans = NULL;
				storage->orphans_writepos = 0;
				storage->orphans_allocsize = 0;
			}
		}
	}
	
	// TODO: verify the data we just loaded
	
	if (!do_reindex) {
		if (bp_blockstorage_rehash(storage) < 0) {
			do_reindex = 1;
		}
	}
	
	if (do_reindex) {
		bp_blockstorage_reindex(storage);
	}
	
	write_log(2, "Main chain contains %d blocks", bp_blockstorage_getheight(storage));
	
	// Open the last block file we can find, so we can append
	
	
	return 0;
}

void bp_blockstorage_deinit(bp_blockstorage_s *storage)
{
	free(storage->mainchain);
	free(storage->orphans);
	if (storage->mainchain_fd) fclose(storage->mainchain_fd);
	if (storage->orphans_fd) fclose(storage->orphans_fd);
	if (storage->mainindex) bp_blockstorage_hashmap_free(storage->mainindex);
	if (storage->orphanindex) bp_blockstorage_hashmap_free(storage->orphanindex);
}


int bp_blockstorage_store(bp_blockstorage_s *storage, char *blockhash, bp_btcblock_header_s *header, ev_uint64_t txn_count, char *txs, size_t txs_len)
{
	// Basically just store it in a btcblk, then index it
	
	return 0;
}

int bp_blockstorage_getfd(bp_blockstorage_s *storage, char *blockhash, bp_blockstorage_fd_s **fd)
{
	return 0;
}

int bp_blockstorage_index(bp_blockstorage_s *storage, char *blockhash, char *prevblock, unsigned int blockfile, unsigned int offset, unsigned int length, unsigned int checksum)
{
	int do_recheck = 0;
	
	// Top of the chain?
	// if so, add it there
	char *top_hash = bp_blockstorage_gettop(storage);
	if (top_hash) {
		if (memcmp(top_hash, prevblock, 32) == 0) {
			// We better add this to the top then
			goto store_top;
		}
	}
	else {
		// Looking for the genesis block
		if (memcmp(blockhash, genesis, 32) == 0) {
			goto store_top;
		}
	}
	
	// Maybe it's just a duplicate?
	if (bp_blockstorage_hasblock(storage, blockhash) > 0) {
		return 0;
	}
	
	// Else? See if we know its parent
	// if not, add it to the orphans
	// if we do:
	if (bp_blockstorage_hasblock(storage, prevblock) == 0) goto store_orphan;
	
	// See if we can trace it back to some place on our main chain
	// if we can: add that whole branch to the main chain, when it beats the height
	// if we can't: add it to the orphans
	
	do_recheck = 1;
	goto store_orphan;
	
store_top:
	{
		// Does it fit?
		if (storage->mainchain_writepos >= storage->mainchain_allocsize) {
			storage->mainchain_allocsize += (10000 * 48);
			storage->mainchain = realloc(storage->mainchain, storage->mainchain_allocsize);
		}
		
		char entry[48];
		memcpy(entry, blockhash, 32);
		memcpy(entry+32, &blockfile, 4);
		memcpy(entry+36, &offset, 4);
		memcpy(entry+40, &length, 4);
		memcpy(entry+44, &checksum, 4);
		
		if (storage->mainchain_fd) {
			int r = fwrite(entry, 48, 1, storage->mainchain_fd);
			assert(r == 1);
			fflush(storage->mainchain_fd);
		}
		
		bp_blockstorage_hashmap_insert(storage->mainindex, blockhash, storage->mainchain_writepos);
		
		memcpy(storage->mainchain + storage->mainchain_writepos, entry, 48);
		storage->mainchain_writepos += 48;
		
		return 0;
	}
	
store_orphan:
	{
		// Does it fit?
		if (storage->orphans_writepos >= storage->orphans_allocsize) {
			storage->orphans_allocsize += (1000 * 80);
			storage->orphans = realloc(storage->orphans, storage->orphans_allocsize);
		}
		
		char entry[80];
		memcpy(entry   , blockhash, 32);
		memcpy(entry+32, prevblock, 32);
		memcpy(entry+64, &blockfile, 4);
		memcpy(entry+68, &offset, 4);
		memcpy(entry+72, &length, 4);
		memcpy(entry+76, &checksum, 4);
		
		if (storage->orphans_fd) {
			int r = fwrite(entry, 80, 1, storage->orphans_fd);
			assert(r == 1);
			fflush(storage->orphans_fd);
		}
		
		bp_blockstorage_hashmap_insert(storage->orphanindex, blockhash, storage->orphans_writepos);
		
		memcpy(storage->orphans + storage->orphans_writepos, entry, 80);
		storage->orphans_writepos += 80;
		
		if (do_recheck) {
			// TODO
		}
		
		return 0;
	}
}

int bp_blockstorage_hasblock(bp_blockstorage_s *storage, char *blockhash)
{
	// TODO: actually check the hashes. With only 6 bytes of hashdata we just can't be sure.
	
	bp_blockstorage_hashnode_s *node = bp_blockstorage_hashmap_getnode(storage->mainindex, blockhash);
	if (node) return 1;
	
	node = bp_blockstorage_hashmap_getnode(storage->orphanindex, blockhash);
	if (node) return 2;
	
	return 0;
}

int bp_blockstorage_reindex(bp_blockstorage_s *storage)
{
	// Lose our current chains
	free(storage->mainchain);
	storage->mainchain = NULL;
	
	free(storage->orphans);
	storage->orphans = NULL;
	
	if (storage->mainchain_fd != NULL) fclose(storage->mainchain_fd);
	storage->mainchain_fd = 0;
	
	if (storage->orphans_fd != NULL) fclose(storage->orphans_fd);
	storage->orphans_fd = 0;
	
	if (storage->mainindex) bp_blockstorage_hashmap_free(storage->mainindex);
	storage->mainindex = NULL;
	
	if (storage->orphanindex) bp_blockstorage_hashmap_free(storage->orphanindex);
	storage->orphanindex = NULL;
	
	storage->mainchain_allocsize = 0;
	storage->orphans_allocsize = 0;
	storage->mainchain_writepos = 0;
	storage->orphans_writepos = 0;
	
	// Create a new index object in memory
	storage->mainchain_allocsize = 10000 * 48;
	storage->orphans_allocsize = 1000 * 80;
	storage->mainchain = malloc(storage->mainchain_allocsize);
	storage->orphans = malloc(storage->orphans_allocsize);
	storage->mainindex = bp_blockstorage_hashmap_new(65536);
	storage->orphanindex = bp_blockstorage_hashmap_new(1024);
	
	// Iterate over the blocks we have
	int blkid;
	for (blkid = 0; blkid < 99999; blkid++) {
		char filename[14];
		sprintf(filename, "blk%.5d.dat", blkid);
		FILE *f = fopen(filename, "rb");
		if (!f) {
			break;
		}
		
		write_log(1, "Indexing %s", filename);
		
		// Index one block
		// TODO: check magic
		char blockhead[8];
		int read = 0;
		while (fread(blockhead, 8, 1, f) == 1) {
			unsigned int length = *(unsigned int*)(blockhead+4);
			if (length == 0) continue;
			
			read += length;
			
			char *block = malloc(length);
			assert(block);
			assert(length >= 80);
			int r = fread(block, length, 1, f);
			assert(r == 1);
			
			// Checksum
			unsigned int checksum;
			unsigned char hash1[SHA256_DIGEST_LENGTH];
			unsigned char hash2[SHA256_DIGEST_LENGTH];
			
			SHA256((unsigned char*)block, length, hash1);
			SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
			checksum = *(unsigned int*)hash2;
			
			SHA256((unsigned char*)block, 80, hash1);
			SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
			
			bp_blockstorage_index(storage, (char*)hash2, block+4, blkid, ftell(f)-length, length, checksum);
			
			free(block);
		}
		
		fclose(f);
	}
	
	// While we now have the index, we still need to write it
	storage->mainchain_fd = fopen("mainchain.dat", "wb");
	storage->orphans_fd = fopen("orphans.dat", "wb");
	
	int r;
	if (storage->mainchain_writepos) {
		r = fwrite(storage->mainchain, storage->mainchain_writepos, 1, storage->mainchain_fd);
		assert(r == 1);
		fflush(storage->mainchain_fd);
	}
	if (storage->orphans_writepos) {
		r = fwrite(storage->orphans, storage->orphans_writepos, 1, storage->orphans_fd);
		assert(r == 1);
		fflush(storage->orphans_fd);
	}
	
	return 0;
}

char *bp_blockstorage_gettop(bp_blockstorage_s *storage)
{
	return bp_blockstorage_getatindex(storage, bp_blockstorage_getheight(storage)-1);
}

char *bp_blockstorage_getatindex(bp_blockstorage_s *storage, unsigned int num)
{
	assert(storage->mainchain);
	if (bp_blockstorage_getheight(storage) <= num) {
		return NULL;
	}
	
	return storage->mainchain + (48 * num);
}

unsigned int bp_blockstorage_getheight(bp_blockstorage_s *storage)
{
	return storage->mainchain_writepos / 48;
}

int bp_blockstorage_rehash(bp_blockstorage_s *storage)
{
	if (storage->mainindex) bp_blockstorage_hashmap_free(storage->mainindex);
	if (storage->orphanindex) bp_blockstorage_hashmap_free(storage->orphanindex);
	
	storage->mainindex = bp_blockstorage_hashmap_new(65536);
	storage->orphanindex = bp_blockstorage_hashmap_new(1024);
	
	int i;
	for (i = 0; i < storage->mainchain_writepos; i += 48) {
		bp_blockstorage_hashmap_insert(storage->mainindex, storage->mainchain + i, i / 48);
	}
	for (i = 0; i < storage->orphans_writepos; i += 80) {
		bp_blockstorage_hashmap_insert(storage->orphanindex, storage->orphans + i, i / 80);
	}
	
	return 0;
}


bp_blockstorage_hashmap_s *bp_blockstorage_hashmap_new(unsigned int size)
{
	bp_blockstorage_hashmap_s *map = malloc(sizeof(bp_blockstorage_hashmap_s));
	memset(map, 0, sizeof(bp_blockstorage_hashmap_s));
	map->nodes = malloc(sizeof(void*) * size);
	memset(map->nodes, 0, sizeof(void*) * size);
	map->size = size;
	
	return map;
}

int bp_blockstorage_hashmap_insert(bp_blockstorage_hashmap_s *map, char *blockhash, unsigned int num)
{
	unsigned int hash = *(unsigned int*)blockhash;
	unsigned int extra = *(unsigned int*)(blockhash+4);
	
	bp_blockstorage_hashnode_s *node = malloc(sizeof(bp_blockstorage_hashnode_s));
	node->checksum = extra;
	node->num = num;
	node->next = NULL;
	
	// insert it
	bp_blockstorage_hashnode_s **inspos = map->nodes + (hash % map->size);
	while (*inspos != NULL) inspos = &(*inspos)->next;
	
	*inspos = node;
	
	return 0;
}

void bp_blockstorage_hashmap_free(bp_blockstorage_hashmap_s *map)
{
	if (map == NULL) return;
	
	unsigned int i;
	for (i = 0; i < map->size; i++) {
		bp_blockstorage_hashnode_s *node = map->nodes[i];
		while (node != NULL) {
			bp_blockstorage_hashnode_s *next = node->next;
			free(node);
			node = next;
		}
	}
	free(map);
}

bp_blockstorage_hashnode_s *bp_blockstorage_hashmap_getnode(bp_blockstorage_hashmap_s *map, char *blockhash)
{
	unsigned int hash = *(unsigned int*)blockhash;
	unsigned int extra = *(unsigned int*)(blockhash+4);
	
	bp_blockstorage_hashnode_s *node = map->nodes[hash % map->size];
	while (node != NULL) {
		if (node->checksum == extra) return node;
		
		node = node->next;
	}
	
	return NULL;
}