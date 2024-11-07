// SPDX-License-Identifier: BSD-3-Clause

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include "block_meta.h"
#include "osmem.h"

#define MALLOC 0
#define CALLOC 0
#define REALLOC 1
#define KB 1024
#define MMAP_THRESHOLD (128 * KB) // 128 KB (32 pages)
#define PREALLOC_SIZE (128 * KB) // 128 KB
#define BLOCK_SIZE sizeof(struct block_meta) // size of a block
#define ALIGNMENT_SIZE 8 // 8 bytes for the alignment
#define ALIGN(x) (((x) + ALIGNMENT_SIZE - 1) & ~(ALIGNMENT_SIZE - 1)) // align macro

/* pointer to the starting point of the heap */
void *base;

struct block_meta *request_space(struct block_meta *previous, size_t size, size_t threshold)
{
	struct block_meta *block;
	size_t allocated_size;

	size = ALIGN(size);
	/* check if the request space is less than the threshold */
	if (BLOCK_SIZE + size < threshold) {
		/* prealloc 128 KB of memory */
		if (!base) {
			block = (struct block_meta *)sbrk(PREALLOC_SIZE);
			allocated_size = PREALLOC_SIZE - BLOCK_SIZE;
		/* if memory is already allocated, alloc the size requested */
		} else {
			block = (struct block_meta *)sbrk(size + BLOCK_SIZE);
			allocated_size = size;
		}

		/* attempt to allocate memory using the sbrk() system call */
		if ((void *)block == (void *) -1) {
			DIE(1, "sbrk failed to allocate memory :(");
			return NULL;
		}

		block->status = STATUS_ALLOC;
	} else {
		/* alloc with mmap if the size request is bigger than the threshold */
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
	/* connect the previous block to the new one */
	if (previous)
		previous->next = block;
	block->size = allocated_size;
	block->next = NULL;
	block->prev = previous;

	return block;
}

void coalesce(void)
{
	struct block_meta *block = (struct block_meta *)base;
	size_t merged_size;

    /* traverse all memory blocks, merging adjacent free blocks */
	while (block && block->next) {
		if (block->status == STATUS_FREE && block->next->status == STATUS_FREE) {
			merged_size = block->next->size + BLOCK_SIZE;
			merged_size = ALIGN(merged_size);
			block->size += merged_size;
			block->next = block->next->next;
			if (block->next)
				block->next->prev = block;
			continue;
		}
		block = block->next;
	}
}

struct block_meta *find_memory_block(struct block_meta **previous, size_t size)
{
	// first coalesce the free blocks, then traverse all the memory blocks
	// and find the smallest one that fits
	coalesce();
	struct block_meta *block = (struct block_meta *)base;
	struct block_meta *best_block = NULL;
	size_t best_size = SIZE_MAX;

	while (block) {
		if (block->status == STATUS_FREE && block->size >= size) {
			if (block->size < best_size) {
				best_size = block->size;
				best_block = block;
			}
		}
		*previous = block;
		block = block->next;
	}

	return best_block;
}

void split(struct block_meta *block, size_t size)
{
	size = ALIGN(size);
	// if another block fits into this one, split the current one
	if (block->size >= size + BLOCK_SIZE + sizeof(char)) {
		struct block_meta *new_block = (struct block_meta *)((char *)block + BLOCK_SIZE + size);

		new_block->size = block->size - size - BLOCK_SIZE;
		new_block->size = ALIGN(new_block->size);

		new_block->status = STATUS_FREE;
		new_block->next = block->next;
		new_block->prev = block;

		if (new_block->next)
			new_block->next->prev = new_block;

		block->size = size;
		block->next = new_block;
	}
}

struct block_meta *expand(void *ptr, size_t size, int where)
{
	struct block_meta *block = (struct block_meta *)((char *)ptr - BLOCK_SIZE);

	struct block_meta *next_block = block->next;

	size = ALIGN(size);

	if (where == REALLOC) {
		if (next_block && next_block->status == STATUS_FREE) {
			if (block->size + next_block->size + BLOCK_SIZE >= size) {
				block->size += next_block->size + BLOCK_SIZE;
				block->next = next_block->next;
				if (next_block->next)
					next_block->next->prev = block;
				return (block + 1);
			}
		}
	}
	// if next_block is null then we need to allocate more memory to expand
	if (!next_block) {
		size_t increment = size - block->size;

		increment = ALIGN(increment);
		if (sbrk(increment) == (void *)-1) {
			DIE(1, "sbrk has failed :(");
			return NULL;
		}
		block->size += increment;
		return (block + 1);
	}
	return NULL;
}

void *os_malloc(size_t size)
{
	if (size <= 0)
		return NULL;

	struct block_meta *block;

	size = ALIGN(size);

	if (!base) {
		block = request_space(NULL, size, MMAP_THRESHOLD);
		if (!block)
			return NULL;
		base = block;
		if (block->size > size)
			split(block, size);
	} else {
		struct block_meta *previous = (struct block_meta *)base;

		block = find_memory_block(&previous, size);
		if (block) {
			if (block->size > size)
				split(block, size);
			block->status = STATUS_ALLOC;
		} else {
			// trying to expand the previous block if it's available
			block = (struct block_meta *) base;

			while (block->next)
				block = block->next;
			if (block->status == STATUS_FREE) {
				block = expand((char *) block + BLOCK_SIZE, size, MALLOC);
				block = block - 1;
				block->status = STATUS_ALLOC;
			} else {
				// no block found call the OS for more space
				block = request_space(previous, size, MMAP_THRESHOLD);
				if (!block)
					return NULL;
			}
		}
	}
	return (block + 1);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block = (struct block_meta *)((char *)ptr - BLOCK_SIZE);

	/* if the block is allocated with mmap, then use munmap, else just set it to FREE */
	if (block->status == STATUS_MAPPED) {
		if (!block->next && !block->prev)
			base = NULL;

		if (block->next)
			block->next->prev = block->prev;

		if (block->prev)
			block->prev->next = block->next;
		munmap(block, block->size + BLOCK_SIZE);
	} else {
		block->status = STATUS_FREE;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (!nmemb || !size)
		return NULL;

	/* check for overflow */
	if (nmemb > SIZE_MAX / size)
		return NULL;

	size_t size_to_be_allocated = nmemb * size;

	if (size_to_be_allocated <= 0)
		return NULL;

	size_to_be_allocated = ALIGN(size_to_be_allocated);

	struct block_meta *block;

	if (!base) {
		block = request_space(NULL, size_to_be_allocated, getpagesize());
		if (!block)
			return NULL;
		base = block;
		if (block->size > size_to_be_allocated)
			split(block, size_to_be_allocated);
	} else {
		struct block_meta *previous = (struct block_meta *)base;

		block = find_memory_block(&previous, size_to_be_allocated);
		// if the block is found and the size is bigger, split it
		if (block) {
			if (block->size > size_to_be_allocated)
				split(block, size_to_be_allocated);
			block->status = STATUS_ALLOC;
		} else {
			// trying to expand the previous block if it's available
			block = (struct block_meta *)base;
			while (block->next)
				block = block->next;
			if (block->status == STATUS_FREE) {
				block = expand((char *) block + BLOCK_SIZE, size_to_be_allocated, CALLOC);
				block = block - 1;
				block->status = STATUS_ALLOC;
			} else {
				// no block found call the OS for more space
				block = request_space(previous, size_to_be_allocated, getpagesize());
				if (!block)
					return NULL;
			}
		}
	}

	memset(block + 1, 0, block->size);
	return block + 1;
}

void *realloc_new_block(struct block_meta *block, void *ptr, size_t size, size_t movable_size)
{
	// set the base to null to prealloc the correct size if its
	// the only block in list
	if (!block->next && !block->prev)
		base = NULL;
	void *new_block = os_malloc(size);

	if (!new_block)
		return NULL;
	memcpy(new_block, ptr, movable_size);
	os_free(ptr);
	return new_block;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = (struct block_meta *)((char *)ptr - BLOCK_SIZE);

	if (block->status == STATUS_FREE)
		return NULL;

	size = ALIGN(size);
	// if size is already the same return
	if (block->size == size)
		return ptr;

	size_t movable_size = (block->size < size) ? block->size : size;

	if (block->status == STATUS_MAPPED) {
		ptr = realloc_new_block(block, ptr, size, movable_size);
	} else {
		// if the block size is bigger, then split the block
		if (block->size > size) {
			split(block, size);
			goto exit;
		} else {
			// if the block size is smaller, try to expand the block
			if (expand(ptr, size, REALLOC))
				return ptr;
		}
		// ultimately, if nothing works, realloc elsewhere
		ptr = realloc_new_block(block, ptr, size, movable_size);
	}
exit:
	return ptr;
}
