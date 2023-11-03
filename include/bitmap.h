#ifndef _BITMAP_H_
#define _BITMAP_H_

#include <stdint.h>
#include <stdlib.h>

typedef enum {
    BITMAP_TYPE_SIMPLE,
    BITMAP_TYPE_HIERARCHICAL
} bitmap_type;

typedef void *(*bitmap_alloc_func)(size_t size);
typedef void (*bitmap_set_func)(void *bitmap, int bit);
typedef int (*bitmap_test_func)(const void *bitmap, int bit);
typedef void (*bitmap_clear_func)(void *bitmap, int bit);
typedef void (*bitmap_free_func)(void *bitmap);

typedef struct {
    bitmap_alloc_func alloc;
    bitmap_set_func set;
    bitmap_test_func test;
    bitmap_clear_func clear;
    bitmap_free_func free;
} bitmap_ops;

typedef struct {
    uint64_t *bits;
    size_t size;
} bitmap;

bitmap *bitmap_alloc(size_t size);
void bitmap_set(bitmap *b, int bit);
int bitmap_test(const bitmap *b, int bit);
void bitmap_clear(bitmap *b, int bit);
void bitmap_free(bitmap *b);

typedef struct {
    uint64_t *top;
    uint64_t **bottom;
    size_t size;
} hbitmap;

hbitmap *hbitmap_alloc(size_t size);
void hbitmap_set(hbitmap *hb, int bit);
int hbitmap_test(const hbitmap *hb, int bit);
void hbitmap_clear(hbitmap *hb, int bit);
void hbitmap_free(hbitmap *hb);

typedef struct {
    void *bitmap;
    bitmap_ops *ops;
} bmap;

bmap *bmap_alloc(size_t size, bitmap_type type);
void bmap_set(bmap *bm, int bit);
int bmap_test(const bmap *bm, int bit);
void bmap_clear(bmap *bm, int bit);
void bmap_free(bmap *bm);

#endif