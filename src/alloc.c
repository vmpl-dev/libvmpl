#include "alloc.h"

void buddy_init(buddy_t *buddy, void *start, void *end) {
    buddy->start = start;
    buddy->end = end;
    memset(buddy->free_lists, 0, sizeof(buddy->free_lists));
    block_t *block = (block_t *)start;
    block->next = NULL;
    block->order = MAX_ORDER;
    buddy->free_lists[MAX_ORDER] = block;
}

void *buddy_alloc(buddy_t *buddy, int size) {
    int order = MAX_ORDER;
    while ((1 << order) > size) {
        order--;
    }
    if (buddy->free_lists[order] == NULL) {
        return NULL;
    }
    block_t *block = buddy->free_lists[order];
    buddy->free_lists[order] = block->next;
    return (void *)(block + 1);
}

void buddy_free(buddy_t *buddy, void *ptr) {
    block_t *block = (block_t *)(ptr - sizeof(block_t));
    block->next = buddy->free_lists[block->order];
    buddy->free_lists[block->order] = block;
}

void slab_init(slab_t *slab, void *start, int block_size, int blocks) {
    slab->start = start;
    slab->block_size = block_size;
    slab->free_blocks = blocks;
    slab->bitmap = (char *)(start + block_size * blocks);
    memset(slab->bitmap, 0, blocks);
}

void *slab_alloc(slab_t *slab) {
    for (int i = 0; i < slab->free_blocks; i++) {
        if (slab->bitmap[i] == 0) {
            slab->bitmap[i] = 1;
            return (void *)(slab->start + i * slab->block_size);
        }
    }
    return NULL;
}

void slab_free(slab_t *slab, void *ptr) {
    int index = ((char *)ptr - (char *)slab->start) / slab->block_size;
    slab->bitmap[index] = 0;
}

void slab_cache_init(slab_cache_t *cache, void *start, void *end)
{
    cache->slabs = NULL;
    cache->start = start;
    cache->end = end;
}

void *slab_cache_alloc(slab_cache_t *cache, int size)
{
    if (cache->slabs == NULL) {
        int blocks = (cache->end - cache->start) / size;
        int block_size = size + sizeof(slab_t) + blocks;
        void *ptr = buddy_alloc(&buddy, block_size);
        if (ptr == NULL) {
            return NULL;
        }
        slab_t *slab = (slab_t *)ptr;
        slab_init(slab, ptr + sizeof(slab_t), size, blocks);
        slab->next = NULL;
        cache->slabs = slab;
    }
    slab_t *slab = cache->slabs;
    void *ptr = slab_alloc(slab);
    if (ptr == NULL) {
        return NULL;
    }
    if (slab->free_blocks == 0) {
        cache->slabs = slab->next;
    }
    return ptr;
}

void slab_cache_free(slab_cache_t *cache, void *ptr)
{
    slab_t *slab = cache->slabs;
    while (slab != NULL) {
        if (ptr >= slab->start && ptr < slab->start + slab->block_size * slab->free_blocks) {
            slab_free(slab, ptr);
            if (slab->free_blocks == 1) {
                cache->slabs = slab->next;
                buddy_free(&buddy, slab);
            }
            return;
        }
        slab = slab->next;
    }
}