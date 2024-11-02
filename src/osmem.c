// SPDX-License-Identifier: BSD-3-Clause

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "block_meta.h"
#include "osmem.h"

#define MMAP_THRESHOLD 128 * 1024 // 128 KB (32 pages)
#define BLOCK_SIZE sizeof(struct block_meta) // size of a block
#define PREALLOC_SIZE (MMAP_THRESHOLD + BLOCK_SIZE) // 128 KB + the size of a block
#define ALIGNMENT_SIZE 8 // 8 bytes for the alignment
#define ALIGN(x) (((x) + ALIGNMENT_SIZE - 1) & ~(ALIGNMENT_SIZE - 1)) // align macro

/* pointer to the starting point of the heap */
void* base;

struct block_meta *request_space(struct block_meta *last, size_t size) {
	struct block_meta *block;
	size_t allocated_size;
	/* check if the request space is less than 32 pages of memory */
	if (BLOCK_SIZE + size < MMAP_THRESHOLD) {
		/* prealloc 128 KB of memory */
		if (!base) {
			block = (struct block_meta *)sbrk(PREALLOC_SIZE);
			allocated_size = PREALLOC_SIZE - BLOCK_SIZE;
		} else {
			block = (struct block_meta *)sbrk(size + BLOCK_SIZE);
			allocated_size = size;
		}
		
		/* attempt to allocate memory using the sbrk() system call */
		if (block == (void*) -1) {
			DIE(1, "sbrk failed to allocate memory :(");
			return NULL;
		}

		block->status = STATUS_ALLOC;
	} else {
		block = (struct block_meta *)mmap(0, size + BLOCK_SIZE, 
										 PROT_READ | PROT_WRITE, 
										 MAP_PRIVATE | MAP_ANONYMOUS, 
										 -1, 0);

		if (block == MAP_FAILED) {
			DIE(1, "mmap failed to allocate memory :(");
			return NULL;
		}

		allocated_size = size;
		block->status = STATUS_MAPPED;
	}
	/* connect the last block to the new one */
	if (last) {
		last->next = block;
	}
	block->size = allocated_size;
	block->next = NULL;
	block->prev = last;
	
	return block;
}

void coalesce_blocks() {
	struct block_meta *block = (struct block_meta *)base;
	size_t merged_size;

	while (block && block->next) {
		/* if i find 2 free blocks one next to each other */
		if (block->status == STATUS_FREE && block->next == STATUS_FREE) {
			merged_size = block->size + block->next->size + BLOCK_SIZE;
			block->size = merged_size;
			block->next = block->next->next;
			/*
				if the next block is not NULL then prev should point to the newly
			   	bigger block of memory
			*/
			if (block->next) {
				block->next->prev = block;
			}
		} else {
			block = block->next;
		}
	}
}


struct block_meta *find_memory_block(struct block_meta **last, size_t size) {
	coalesce_blocks();

	struct block_meta *block = (struct block_meta *)base;
	while (block && !(block->status && block->size >= size)) {
		*last = block;
		block = block->next;
	}
	return block;
}

void split_block(struct block_meta *block, size_t size) {
	size = ALIGN(size);

	/* check if there is enough space */
	if (block->size <= size + BLOCK_SIZE) {
		return;
	}

	/* calculate the remaining space, and if there is no space for a new 
	   block then return
	*/
	size_t remaining_size = block->size - size - BLOCK_SIZE;
	if (remaining_size < BLOCK_SIZE) {
		return;
	}

	struct block_meta *new_block = (struct block_meta *)((char *)block + size + BLOCK_SIZE);
	
	new_block->size = remaining_size;
	new_block->status = STATUS_FREE;
	
	new_block->next = block->next;
	new_block->prev = block;
	if (new_block->next) {
		new_block->next->prev = new_block;
	}

	block->size = size;
	block->next = new_block;
}

void *os_malloc(size_t size)
{
	if (size <= 0)
		return NULL;
	
	struct block_meta *block;
	size = ALIGN(size);
	if (!base) {
		block = request_space(NULL, size);
		if (!block) {
			return NULL;
		}
		base = block;
	} else {
		struct block_meta *last = (struct block_meta *)base;
		block = find_memory_block(&last, size);
		if (!block) {
			block = request_space(last, size);
			if (!block) {
				return NULL;
			}
		}
	}

	if (block->size > size) {
        split_block(block, size);
    }
	
	block->status = STATUS_ALLOC;
	return (block + 1);
}

void os_free(void *ptr)
{
	
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (!nmemb || !size)
		return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		os_malloc(size);
	if (!size)
		os_free(ptr);
}
