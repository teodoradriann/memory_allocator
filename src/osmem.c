// SPDX-License-Identifier: BSD-3-Clause

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include "block_meta.h"
#include "osmem.h"

#define MMAP_THRESHOLD (128 * 1024) // 128 KB (32 pages)
#define BLOCK_SIZE sizeof(struct block_meta) // size of a block
#define PREALLOC_SIZE (MMAP_THRESHOLD) // 128 KB
#define ALIGNMENT_SIZE 8 // 8 bytes for the alignment
#define ALIGN(x) (((x) + ALIGNMENT_SIZE - 1) & ~(ALIGNMENT_SIZE - 1)) // align macro

/* pointer to the starting point of the heap */
void *base;

struct block_meta *request_space(struct block_meta *last, size_t size, size_t threshold)
{
	struct block_meta *block;
	size_t allocated_size;
	/* check if the request space is less than the threshold */
	if (BLOCK_SIZE + size < threshold) {
		/* prealloc 128 KB of memory */
		if (!base) {
			block = (struct block_meta *)sbrk(PREALLOC_SIZE);
			allocated_size = PREALLOC_SIZE - BLOCK_SIZE;
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
	if (last)
		last->next = block;
	block->size = allocated_size;
	block->next = NULL;
	block->prev = last;

	return block;
}

void coalesce_blocks(void)
{
	struct block_meta *block = (struct block_meta *)base;
	size_t merged_size;

	while (block) {
		struct block_meta *next_block = block->next;

		if (block->status == STATUS_FREE && next_block && next_block->status == STATUS_FREE) {
			merged_size = block->size + block->next->size + BLOCK_SIZE;
			merged_size = ALIGN(merged_size);
			block->size = merged_size;
			block->next = block->next->next;
			if (block->next)
				block->next->prev = block;
		} else {
			block = block->next;
		}
	}
}

struct block_meta *find_memory_block(struct block_meta **last, size_t size)
{
	coalesce_blocks();
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
		*last = block;
		block = block->next;
	}

	return best_block;
}

void split_block(struct block_meta *block, size_t size)
{
	size = ALIGN(size);

	if (block->size >= size + BLOCK_SIZE + ALIGNMENT_SIZE) {
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

void *expand_block(void *ptr, size_t size)
{
	coalesce_blocks();
	struct block_meta *block = (struct block_meta *)((char *)ptr - BLOCK_SIZE);

	struct block_meta *next_block = block->next;

	size = ALIGN(size);

	if (next_block && next_block->status == STATUS_FREE) {
		if (block->size + next_block->size + BLOCK_SIZE >= size) {
			block->size += next_block->size + BLOCK_SIZE;
			block->next = next_block->next;
			if (next_block->next)
				next_block->next->prev = block;
			return ptr;
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
		return block + 1;
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
			split_block(block, size);
	} else {
		struct block_meta *last = (struct block_meta *)base;

		block = find_memory_block(&last, size);
		if (block) {
			if (block->size > size)
				split_block(block, size);
			block->status = STATUS_ALLOC;
		} else {
			// trying to expand the last block if it's available
			block = (struct block_meta *) base;

			while (block->next)
				block = block->next;
			if (block->status == STATUS_FREE) {
				block = (struct block_meta *)expand_block(block, size - block->size);
			} else {
				// no block found call the OS for more space
				block = request_space(last, size, MMAP_THRESHOLD);
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
			split_block(block, size_to_be_allocated);
	} else {
		struct block_meta *last = (struct block_meta *)base;

		block = find_memory_block(&last, size_to_be_allocated);
		if (block) {
			if (block->size > size_to_be_allocated)
				split_block(block, size_to_be_allocated);
			block->status = STATUS_ALLOC;
		} else {
			// trying to expand the last block if it's available
			block = (struct block_meta *)base;
			while (block->next)
				block = block->next;
			if (block->status == STATUS_FREE) {
				block = (struct block_meta *)expand_block(block, size_to_be_allocated - block->size);
			} else {
				// no block found call the OS for more space
				block = request_space(last, size_to_be_allocated, getpagesize());
				if (!block)
					return NULL;
			}
		}
	}

	memset(block + 1, 0, block->size);
	return block + 1;
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
		void *new_block = os_malloc(size);

		if (!new_block)
			return NULL;
		memcpy(new_block, ptr, movable_size);
		os_free(ptr);
		ptr = new_block;
		goto exit;
	} else {
		// if the block size is bigger, then split the block
		if (block->size > size) {
			split_block(block, size);
			goto exit;
		} else {
			void *new_block = expand_block(ptr, size);

			if (new_block)
				return new_block;
		}
		void *new_block = os_malloc(size);

		if (!new_block)
			return NULL;
		memcpy(new_block, ptr, movable_size);
		os_free(ptr);
		ptr = new_block;
		goto exit;
	}
exit:
	return ptr;
}
