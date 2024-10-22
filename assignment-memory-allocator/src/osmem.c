// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <unistd.h>
#include <errno.h>
#include <../utils/block_meta.h>
#include <syscall.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

#define MMAP_THRESHOLD (128*1024)
#define METADATA_SIZE sizeof(struct block_meta)
#define MAP_ANONYMOUS 0x20
#define PAGE_SIZE getpagesize()
#define padding_struct (8 - (METADATA_SIZE % 8))

int status_prealloc;

struct block_meta *head;
struct block_meta *tail;

void coalesce_free_blocks(void)
{
	struct block_meta *aux = head;

	if (aux) {
		while (aux && aux->next) {
			struct block_meta *aux2 = aux->next;

			if (aux->status == STATUS_FREE && aux2->status == STATUS_FREE && aux2->next != NULL) {
				aux->size += aux2->size;
				if (aux2->next != NULL) {
					struct block_meta *aux3 = aux2->next;

					aux3->prev = aux;
					aux->next = aux3;
				}
			} else {
				aux = aux->next;
			}
		}
		if (tail != aux)
			tail = aux;
	}
}

struct block_meta *find_best_block(size_t size)
{
	struct block_meta *ptr = head;
	struct block_meta *best = NULL;

	while (ptr != NULL) {
		if (ptr->size >= size) {
			if (best == NULL && ptr->status == STATUS_FREE)
				best = ptr;
			else if ((ptr != NULL) && (best != NULL))
				if (ptr->size < best->size) {
					if (ptr->status == STATUS_FREE)
						best = ptr;
				}
		}
		ptr = ptr->next;
	}
	return best;
}

struct block_meta *split_block(struct block_meta *block, size_t alloc_size)
{
	if (block == NULL)
		return NULL;
	struct block_meta *aux = NULL;

	if (block->next)
		aux = block->next;

	if (block->size - alloc_size > METADATA_SIZE) {
		struct block_meta *new_block = (struct block_meta *) ((char *)block + alloc_size);

		if (new_block) {
			new_block->next = NULL;
			new_block->size = block->size - alloc_size;

			int new_size = new_block->size;

			if (new_size % 8)
				new_size += 8 - (new_size % 8);

			new_block->size = new_size;
			new_block->prev = block;
			block->size = alloc_size;

			if (aux != NULL && new_block != NULL) {
				new_block->next = aux;
				aux->prev = new_block;
			} else if (new_block) {
				tail = new_block;
			}
			new_block->status = STATUS_FREE;
			block->next = new_block;
		}
	}
	return block;
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	if (size == 0)
		return NULL;
	size_t total_size = 0;

	if (METADATA_SIZE % 8)
		total_size += METADATA_SIZE + padding_struct;
	else
		total_size += METADATA_SIZE;
	if (size % 8)
		total_size += size + (8 - (size % 8));
	else
		total_size += size;
	if (total_size < MMAP_THRESHOLD) {
		if (status_prealloc == 0) {
			struct block_meta *block = NULL;

			block = sbrk(MMAP_THRESHOLD);
			if (block == (void *) -1) {
				DIE(block == (void *) -1, "sbrk");
				return NULL;
			}
			status_prealloc = 1;
			block->size = MMAP_THRESHOLD;
			block->status = STATUS_FREE;
			if (head == NULL) {
				head = block;
				tail = block;
				block->next = NULL;
				block->prev = NULL;
			} else {
				tail->next = block;
				block->prev = tail;
				block->next = NULL;
				tail = block;
			}
		}
		coalesce_free_blocks();
		struct block_meta *best_block = find_best_block(total_size);

		if (best_block == NULL) {
			best_block = (struct block_meta *) sbrk(total_size);
			if (best_block == (void *) -1) {
				DIE(best_block == (void *) -1, "sbrk");
				return NULL;
			}
			best_block->size = total_size;
			best_block->status = STATUS_ALLOC;
			if (head == NULL) {
				head = best_block;
				tail = best_block;
				best_block->next = NULL;
				best_block->prev = NULL;
			} else {
				tail->next = best_block;
				best_block->prev = tail;
				best_block->next = NULL;
				tail = best_block;
			}
		} else {
			best_block->status = STATUS_ALLOC;
			best_block = split_block(best_block, total_size);
		}
		if (best_block != NULL)
			return (void *) (best_block + 1);
		return NULL;
	}
		struct block_meta *block = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (block == MAP_FAILED) {
				DIE(block == MAP_FAILED, "mmap");
				return NULL;
			}
			block->size = total_size;
			block->status = STATUS_MAPPED;
			if (head == NULL) {
				head = block;
				tail = block;
				block->next = NULL;
				block->prev = NULL;
			} else {
				tail->next = block;
				block->prev = tail;
				block->next = NULL;
				tail = block;
			}
			if (block != NULL)
				return (void *) (block + 1);
			return NULL;
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (ptr) {
		int struct_size = METADATA_SIZE;
	if (struct_size % 8)
		struct_size += 8 - (METADATA_SIZE % 8);
	struct block_meta *block = (struct block_meta *)((char *)ptr - struct_size);

	if (block != NULL) {
		if (block->status == STATUS_MAPPED) {
			if (block == head) {
				if (head->next) {
					head = head->next;
					head->prev = NULL;
				} else {
					head = NULL;
				}
			} else if (block == tail) {
				if (tail->prev) {
					tail = tail->prev;
					tail->next = NULL;
				} else {
					tail = NULL;
				}
			} else {
				struct block_meta *aux = block->prev;
				struct block_meta *aux2 = block->next;

				if (aux != NULL && aux2 != NULL) {
					aux->next = aux2;
					aux2->prev = aux;
				}
			}
			int size = block->size;
			int ret = munmap(block, size);

			if (ret == -1) {
				DIE(ret == -1, "munmap");
				return;
			}
		} else {
			block->status = STATUS_FREE;
		}
	}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	if (nmemb == 0 || size == 0)
		return NULL;
	size_t total_size = nmemb * size + METADATA_SIZE;

	if (total_size % 8)
		total_size += 8 - (total_size % 8);
	if (METADATA_SIZE % 8)
		total_size += 8 - (METADATA_SIZE % 8);
	if ((int) total_size < PAGE_SIZE) {
		if (status_prealloc == 0) {
			struct block_meta *block = NULL;

			block = sbrk(MMAP_THRESHOLD);
			if (block == (void *) -1) {
				DIE(block == (void *) -1, "sbrk");
				return NULL;
			}
			status_prealloc = 1;
			block->size = MMAP_THRESHOLD;
			block->status = STATUS_FREE;
			if (head == NULL) {
				head = block;
				tail = block;
				block->next = NULL;
				block->prev = NULL;
			} else {
				tail->next = block;
				block->prev = tail;
				block->next = NULL;
				tail = block;
			}
			memset((char *)block + METADATA_SIZE, 0, block->size - METADATA_SIZE);
		}
		coalesce_free_blocks();
		struct block_meta *best_block = find_best_block(total_size);

		if (best_block == NULL) {
			best_block = (struct block_meta *) sbrk(total_size);
			if (best_block == (void *) -1) {
				DIE(best_block == (void *) -1, "sbrk");
				return NULL;
			}
			best_block->size = total_size;
			best_block->status = STATUS_ALLOC;
			if (head == NULL) {
				head = best_block;
				tail = best_block;
				best_block->next = NULL;
				best_block->prev = NULL;
			} else {
				tail->next = best_block;
				best_block->prev = tail;
				best_block->next = NULL;
				tail = best_block;
			}
		} else {
			best_block->status = STATUS_ALLOC;
			best_block = split_block(best_block, total_size);
			memset((char *)best_block + METADATA_SIZE, 0, total_size - METADATA_SIZE);
		}
		if (best_block != NULL) {
			memset((char *)best_block + METADATA_SIZE, 0, total_size - METADATA_SIZE);
			return (void *) (best_block + 1);
		}
		return NULL;
	}
		struct block_meta *block = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (block == MAP_FAILED) {
				DIE(block == MAP_FAILED, "mmap");
				return NULL;
			}
			block->size = total_size;
			block->status = STATUS_MAPPED;
			if (head == NULL) {
				head = block;
				tail = block;
				block->next = NULL;
				block->prev = NULL;
			} else {
				tail->next = block;
				block->prev = tail;
				block->next = NULL;
				tail = block;
			}
			if (block != NULL) {
				memset((char *)block + METADATA_SIZE, 0, total_size - METADATA_SIZE);
				return (void *) (block + 1);
			}
			return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (ptr == NULL)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	size_t total_size = 0;

	if (METADATA_SIZE % 8)
		total_size += METADATA_SIZE + padding_struct;
	else
		total_size += METADATA_SIZE;
	if (size % 8)
		total_size += size + (8 - (size % 8));
	else
		total_size += size;
	struct block_meta *block = (struct block_meta *) ((char *)ptr - METADATA_SIZE);

	if (block->size == total_size)
		return (void *) (block + 1);
	if (block->status == STATUS_FREE)
		return NULL;
	if (total_size < block->size) {
		block = split_block(block, total_size);
		if (block != NULL)
			return (void *) (block + 1);
		return NULL;
	}
	if (block->status == STATUS_ALLOC) {
		coalesce_free_blocks();
		size_t extra_size = total_size - block->size;
		size_t size_coalesce = 0;
		struct block_meta *copie = block;

		while (block->next != NULL && (block->next)->status == STATUS_FREE && size_coalesce < extra_size) {
			struct block_meta *aux = block->next;

			if (aux == NULL)
				break;
			size_coalesce += aux->size;
			copie->size += aux->size;

			if (aux->next != NULL) {
				struct block_meta *aux2 = aux->next;

				if (aux2 == NULL)
					break;
				aux2->prev = copie;
				copie->next = aux2;
				block = block->next;
			} else {
				tail = block->next;
			}
		}
		if (size_coalesce >= extra_size) {
			if (copie->size % 8)
				copie->size += 8 - (copie->size % 8);
			if (copie->size - total_size > METADATA_SIZE)
				copie = split_block(copie, total_size);
			if (copie != NULL)
				return (void *) (copie + 1);
			return NULL;
		}
			void *new_block = os_malloc(total_size);

			if (new_block != NULL && ptr != NULL) {
				struct block_meta *blk = (struct block_meta *)((char *)ptr - METADATA_SIZE);

				memcpy(new_block, ptr, blk->size - METADATA_SIZE);
				os_free(blk);
				return (void *)(new_block + 1);
			}
			return NULL;
		} else if (block->status == STATUS_MAPPED) {
			void *new_block = os_malloc(total_size);

			if (new_block != NULL && ptr != NULL) {
				struct block_meta *blk = (struct block_meta *)((char *)ptr - METADATA_SIZE);

				memcpy(new_block, ptr, blk->size - METADATA_SIZE);
				os_free(blk);
				return (void *)(new_block + 1);
			}
			return NULL;
		}
	return NULL;
}
