#ifndef __CACHE_H__
#define __CACHE_H__

#include <stddef.h>

struct mem_cache_t {
    void *data;
    size_t size;
    size_t capacity;
};

struct mem_cache_t *mem_cache_create(size_t capacity);
void mem_cache_destroy(struct mem_cache_t *cache);
void mem_cache_clear(struct mem_cache_t *cache);
void mem_cache_resize(struct mem_cache_t *cache, size_t capacity);
void mem_cache_push_back(struct mem_cache_t *cache, void *data, size_t size);
void mem_cache_pop_back(struct mem_cache_t *cache, void *data, size_t size);
void mem_cache_insert(struct mem_cache_t *cache, size_t index, void *data, size_t size);
void mem_cache_erase(struct mem_cache_t *cache, size_t index, size_t size);
void mem_cache_swap(struct mem_cache_t *cache, size_t index1, size_t index2, size_t size);
void mem_cache_copy(struct mem_cache_t *cache, size_t index1, size_t index2, size_t size);
void mem_cache_move(struct mem_cache_t *cache, size_t index1, size_t index2, size_t size);
void mem_cache_reverse(struct mem_cache_t *cache, size_t size);

#endif // __CACHE_H__