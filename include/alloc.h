#ifndef __ALLOC_H__
#define __ALLOC_H__

#include <stddef.h>

#define MAX_ORDER 8
#define MIN_SIZE (1 << MAX_ORDER)

typedef struct block {
    struct block *next;
    int order;
} block_t;

typedef struct {
    block_t *free_lists[MAX_ORDER + 1];
    void *start;
    void *end;
} buddy_t;

typedef struct slab {
    struct slab *next;
    void *start;
    int block_size;
    int free_blocks;
    char *bitmap;
} slab_t;

typedef struct {
    slab_t *slabs;
    void *start;
    void *end;
} slab_cache_t;

void buddy_init(buddy_t *buddy, void *start, void *end);
void *buddy_alloc(buddy_t *buddy, int size);
void buddy_free(buddy_t *buddy, void *ptr);

void slab_init(slab_t *slab, void *start, int block_size, int blocks);
void *slab_alloc(slab_t *slab);
void slab_free(slab_t *slab, void *ptr);

void slab_cache_init(slab_cache_t *cache, void *start, void *end);
void *slab_cache_alloc(slab_cache_t *cache, int size);
void slab_cache_free(slab_cache_t *cache, void *ptr);