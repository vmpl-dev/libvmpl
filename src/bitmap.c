#include <string.h>
#include <stdlib.h>

#include "bitmap.h"

bitmap *bitmap_alloc(size_t size) {
    bitmap *b = malloc(sizeof(bitmap));
    if (!b) return NULL;

    b->bits = calloc(size / 64, sizeof(uint64_t));
    if (!b->bits) {
        free(b);
        return NULL;
    }

    b->size = size;
    return b;
}

void bitmap_set(bitmap *b, int bit) {
    b->bits[bit / 64] |= (1ULL << (bit % 64));
}

int bitmap_test(const bitmap *b, int bit) {
    return (b->bits[bit / 64] & (1ULL << (bit % 64))) != 0;
}

int bitmap_query(const bitmap *b, int bit) {
    if (bit < 0 || bit >= b->size) {
        // Out of bounds
        return -1;
    }

    return bitmap_test(b, bit);
}

int bitmap_find_first_zero(const bitmap *b) {
    for (size_t i = 0; i < b->size / 64; i++) {
        if (b->bits[i] != 0xFFFFFFFFFFFFFFFF) {
            for (size_t j = 0; j < 64; j++) {
                if ((b->bits[i] & (1ULL << j)) == 0) {
                    return i * 64 + j;
                }
            }
        }
    }

    return -1;
}

void bitmap_clear(bitmap *b, int bit) {
    b->bits[bit / 64] &= ~(1ULL << (bit % 64));
}

void bitmap_free(bitmap *b) {
    free(b->bits);
    free(b);
}

bitmap_ops bitmap_simple_ops = {
    .alloc = (bitmap_alloc_func)bitmap_alloc,
    .set = (bitmap_set_func)bitmap_set,
    .test = (bitmap_test_func)bitmap_test,
    .query = (bitmap_query_func)bitmap_query,
    .find_first_zero = (bitmap_find_first_zero_func)bitmap_find_first_zero,
    .clear = (bitmap_clear_func)bitmap_clear,
    .free = (bitmap_free_func)bitmap_free
};

hbitmap *hbitmap_alloc(size_t size) {
    hbitmap *hb = malloc(sizeof(hbitmap));
    if (!hb) return NULL;

    hb->size = size;
    hb->top = bitmap_alloc(size);
    if (!hb->top) {
        free(hb);
        return NULL;
    }

    hb->bottom = malloc(size * sizeof(uint64_t *));
    if (!hb->bottom) {
        free(hb->top);
        free(hb);
        return NULL;
    }

    for (size_t i = 0; i < size; i++) {
        hb->bottom[i] = bitmap_alloc(size);
        if (!hb->bottom[i]) {
            for (size_t j = 0; j < i; j++) {
                free(hb->bottom[j]);
            }
            free(hb->bottom);
            free(hb->top);
            free(hb);
            return NULL;
        }
    }

    return hb;
}

void hbitmap_set(hbitmap *hb, int bit) {
    int top_index = bit / hb->size;
    int bottom_index = bit % hb->size;

    bitmap_set(hb->top, top_index);
    bitmap_set(hb->bottom[top_index], bottom_index);
}

int hbitmap_test(const hbitmap *hb, int bit) {
    int top_index = bit / hb->size;
    int bottom_index = bit % hb->size;

    if (bitmap_test(hb->top, top_index)) {
        return bitmap_test(hb->bottom[top_index], bottom_index);
    } else {
        return 0;
    }
}

int hbitmap_query(const hbitmap *hb, int bit) {
    if (bit < 0 || bit >= hb->size * hb->size) {
        // Out of bounds
        return -1;
    }

    return hbitmap_test(hb, bit);
}

int hbitmap_find_first_zero(const hbitmap *hb) {
    int top_index = bitmap_find_first_zero(hb->top);
    if (top_index == -1) {
        return -1;
    }

    int bottom_index = bitmap_find_first_zero(hb->bottom[top_index]);
    if (bottom_index == -1) {
        return -1;
    }

    return top_index * hb->size + bottom_index;
}

void hbitmap_clear(hbitmap *hb, int bit) {
    int top_index = bit / hb->size;
    int bottom_index = bit % hb->size;

    bitmap_clear(hb->bottom[top_index], bottom_index);

    // If the bottom bitmap is now empty, clear the bit in the top bitmap
    for (int i = 0; i < hb->size; i++) {
        if (bitmap_test(hb->bottom[top_index], i)) {
            return;
        }
    }

    bitmap_clear(hb->top, top_index);
}

void hbitmap_free(hbitmap *hb) {
    if (hb) {
        bitmap_free(hb->top);
        for (size_t i = 0; i < hb->size; i++) {
            bitmap_free(hb->bottom[i]);
        }
        free(hb->bottom);
        free(hb);
    }
}

bitmap_ops bitmap_hierarchical_ops = {
    .alloc = (bitmap_alloc_func)hbitmap_alloc,
    .set = (bitmap_set_func)hbitmap_set,
    .test = (bitmap_test_func)hbitmap_test,
    .query = (bitmap_query_func)hbitmap_query,
    .find_first_zero = (bitmap_find_first_zero_func)hbitmap_find_first_zero,
    .clear = (bitmap_clear_func)hbitmap_clear,
    .free = (bitmap_free_func)hbitmap_free
};

bmap *bmap_alloc(size_t size, bitmap_type type) {
    bmap *bm = malloc(sizeof(bmap));
    if (!bm) return NULL;

    if (type == BITMAP_TYPE_SIMPLE) {
        bm->ops = &bitmap_simple_ops;
    } else {
        bm->ops = &bitmap_hierarchical_ops;
    }

    bm->bitmap = bm->ops->alloc(size);
    if (!bm->bitmap) {
        free(bm);
        return NULL;
    }

    return bm;
}

void bmap_set(bmap *bm, int bit) {
    bm->ops->set(bm->bitmap, bit);
}

int bmap_test(const bmap *bm, int bit) {
    return bm->ops->test(bm->bitmap, bit);
}

int bmap_query(const bmap *bm, int bit) {
    return bm->ops->query(bm->bitmap, bit);
}

int bmap_find_first_zero(const bmap *bm) {
    return bm->ops->find_first_zero(bm->bitmap);
}

void bmap_clear(bmap *bm, int bit) {
    bm->ops->clear(bm->bitmap, bit);
}

void bmap_free(bmap *bm) {
    bm->ops->free(bm->bitmap);
    free(bm);
}
