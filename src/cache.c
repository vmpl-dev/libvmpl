#include "cache.h"

#include <stdlib.h>
#include <string.h>

struct mem_cache_t *mem_cache_create(size_t capacity)
{
    struct mem_cache_t *cache = malloc(sizeof(struct mem_cache_t));
    if (cache == NULL) {
        return NULL;
    }
    cache->capacity = capacity;
    cache->size = 0;
    cache->data = malloc(capacity);
    if (cache->data == NULL) {
        free(cache);
        return NULL;
    }
    return cache;
}

void mem_cache_destroy(struct mem_cache_t *cache)
{
    free(cache->data);
    free(cache);
}

void mem_cache_clear(struct mem_cache_t *cache)
{
    cache->size = 0;
}

void mem_cache_resize(struct mem_cache_t *cache, size_t capacity)
{
    cache->capacity = capacity;
    void *new_data = realloc(cache->data, capacity);
    if (new_data != NULL) {
        cache->data = new_data;
    }
}

void mem_cache_push_back(struct mem_cache_t *cache, void *data, size_t size)
{
    if (cache->size + size > cache->capacity) {
        mem_cache_resize(cache, cache->capacity * 2);
    }
    memmove(cache->data + size, cache->data, cache->size);
    memcpy(cache->data, data, size);
    cache->size += size;
}

void mem_cache_pop_back(struct mem_cache_t *cache, void *data, size_t size)
{
    memcpy(data, cache->data + cache->size - size, size);
    memmove(cache->data + size, cache->data + size, cache->size - size);
    cache->size -= size;
}

void mem_cache_insert(struct mem_cache_t *cache, size_t index, void *data, size_t size)
{
    if (cache->size + size > cache->capacity) {
        mem_cache_resize(cache, cache->capacity * 2);
    }
    memmove(cache->data + index + size, cache->data + index, cache->size - index);
    memcpy(cache->data + index, data, size);
    cache->size += size;
}

void mem_cache_erase(struct mem_cache_t *cache, size_t index, size_t size)
{
    if (index + size > cache->size) {
        // Invalid erase range
        return;
    }

    memmove(cache->data + index, cache->data + index + size, cache->size - index - size);
    cache->size -= size;
}

void mem_cache_swap(struct mem_cache_t *cache, size_t index1, size_t index2, size_t size)
{
    if (index1 + size > cache->size || index2 + size > cache->size) {
        // Invalid swap range
        return;
    }

    void *temp = malloc(size);
    memcpy(temp, cache->data + index1, size);
    memcpy(cache->data + index1, cache->data + index2, size);
    memcpy(cache->data + index2, temp, size);
    free(temp);
}

void mem_cache_copy(struct mem_cache_t *cache, size_t index1, size_t index2, size_t size)
{
    if (index1 + size > cache->size || index2 + size > cache->size) {
        // Invalid copy range
        return;
    }

    memcpy(cache->data + index2, cache->data + index1, size);
}

void mem_cache_move(struct mem_cache_t *cache, size_t index1, size_t index2, size_t size)
{
    if (index1 + size > cache->size || index2 + size > cache->size) {
        // Invalid move range
        return;
    }

    memmove(cache->data + index2, cache->data + index1, size);
}

void mem_cache_reverse(struct mem_cache_t *cache, size_t size)
{
    if (size > cache->size) {
        // Invalid reverse range
        return;
    }

    size_t i;
    for (i = 0; i < size / 2; i++) {
        mem_cache_swap(cache, i, size - i - 1, 1);
    }
}
