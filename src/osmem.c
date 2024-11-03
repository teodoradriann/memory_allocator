// SPDX-License-Identifier: BSD-3-Clause

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include "block_meta.h"
#include "osmem.h"

#define MMAP_THRESHOLD 128 * 1024 // 128 KB (32 pages)
#define BLOCK_SIZE sizeof(struct block_meta) // size of a block
#define PREALLOC_SIZE (MMAP_THRESHOLD) // 128 KB
#define ALIGNMENT_SIZE 8 // 8 bytes for the alignment
#define ALIGN(x) (((x) + ALIGNMENT_SIZE - 1) & ~(ALIGNMENT_SIZE - 1)) // align macro

/* pointer to the starting point of the heap */
void* base = NULL;

struct block_meta *request_space(struct block_meta *last, size_t size, size_t threshold) {
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
	allocated_size = ALIGN(allocated_size);
	block->size = allocated_size;
	block->next = NULL;
	block->prev = last;

	return block;
}

void coalesce_blocks() {
	struct block_meta *block = (struct block_meta *)base;
	size_t merged_size;
	
	while (block) {
        struct block_meta *next_block = block->next;
        if (block->status == STATUS_FREE && next_block && next_block->status == STATUS_FREE) {
				merged_size = block->size + block->next->size + BLOCK_SIZE;
				merged_size = ALIGN(merged_size);
                block->size = merged_size;
                block->next = block->next->next;
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

void split_block(struct block_meta *block, size_t size) {
    /* calculate the remaining space after splitting */
    size_t remaining_size = block->size - size;
    if (remaining_size <= BLOCK_SIZE) {
        return;
    }
	remaining_size = ALIGN(remaining_size);
    /* create a new block for the remaining space */
    struct block_meta *new_block = (struct block_meta *)((char *)block + size + BLOCK_SIZE);

    new_block->size = remaining_size - BLOCK_SIZE;
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
        block = request_space(NULL, size, MMAP_THRESHOLD);
        if (!block) {
            return NULL;
        }
        base = block;
		if (block->size > size)
			split_block(block, size);
    } else {
        struct block_meta *last = (struct block_meta *)base;
        block = find_memory_block(&last, size);
        if (!block) {
            block = request_space(last, size, MMAP_THRESHOLD);
            if (!block) {
                return NULL;
            }
        } else {
			if (block->size > size) {
				split_block(block, size);
			}
			else {
				block->size = size;
			}
			block->status = STATUS_ALLOC;
		}
    }
    return (void *)(block + 1);
}


void os_free(void *ptr)
{
    if (!ptr)
        return;

    struct block_meta *block = (struct block_meta *) ptr - 1;

    /* if the block is allocated with mmap, then use munmap, else just set it to FREE */
    if (block->status == STATUS_MAPPED) {
		if (!block->next && !block->prev) {
			base = NULL;
		}
		if (block->next) {
			block->next->prev = block->prev;
		}
		if (block->prev) {
			block->prev->next = block->next;
		}
        munmap(block, block->size + BLOCK_SIZE);
    } else {
        block->status = STATUS_FREE;
    }
}


void *os_calloc(size_t nmemb, size_t size)
{
	if (!nmemb || !size) {
		return NULL;
	}

	if (nmemb > SIZE_MAX / size) {
        return NULL;
    }

	size_t size_to_be_allocated = nmemb * size;
	size_to_be_allocated = ALIGN(size_to_be_allocated);

	struct block_meta *block;
	if (!base) {
		block = request_space(NULL, size_to_be_allocated, getpagesize());
		if (!block) {
			return NULL;
		}
		base = block;
	} else {
		struct block_meta *last = (struct block_meta *)base;
		block = find_memory_block(&last, size_to_be_allocated);
		if (!block) {
			block = request_space(last, size_to_be_allocated, getpagesize());
			if (!block) {
				return NULL;
			}
		} else {
			if (block->size > size_to_be_allocated) {
                split_block(block, size_to_be_allocated);
            } else {
				block->size = size_to_be_allocated;
			}
			block->status = STATUS_ALLOC;
		}
	}

	memset(block + 1, 0, block->size);
	return (void *)(block + 1);
}

void *expand_block(void *ptr, size_t size) {
    coalesce_blocks();
    struct block_meta *block = (struct block_meta *)ptr - 1;
    struct block_meta *next_block = block->next;

    if (next_block && next_block->status == STATUS_FREE) {
        if (block->size + next_block->size + BLOCK_SIZE >= size) {
            block->size += next_block->size + BLOCK_SIZE;
            block->next = next_block->next;
            if (next_block->next) {
                next_block->next->prev = block;
            }
            return ptr;
        }
    }

    // if next_block is null then we need to allocate more memory to expand
    if (!next_block) {
		if (block->size < size) {
			void *new_block = sbrk(size - block->size);
			if (new_block == (void *)-1) {
				DIE(1, "sbrk failed to allocate memory :(");
				return NULL;
			}
			block->size = size;
			return ptr;
		}
    }
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
    if (!ptr) {
        return os_malloc(size);
    }

    if (!size) {
        os_free(ptr);
        return NULL;
    }
	
	size = ALIGN(size);
    struct block_meta *block = (struct block_meta *)ptr - 1;

    if (block->status == STATUS_FREE) {
        return NULL;
    }

    if (block->size >= size) {
        split_block(block, size);
        return ptr;
    }

	void *expanded_ptr = expand_block(ptr, size);
	if (expanded_ptr) {
		return expanded_ptr;
	}

	// if the expanding is not possible, alloc another memory zone
	void *new_ptr = os_malloc(size);
	if (!new_ptr) {
		return NULL;
	}
	memcpy(new_ptr, ptr, block->size);
	os_free(ptr);
	return new_ptr;
}