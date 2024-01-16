#include <check.h>
#include "cache.h"

START_TEST(test_mem_cache_create)
{
    struct mem_cache_t *cache = mem_cache_create(10);
    ck_assert_ptr_nonnull(cache);
    ck_assert_int_eq(cache->capacity, 10);
    mem_cache_destroy(cache);
}
END_TEST

START_TEST(test_mem_cache_push_and_pop)
{
    struct mem_cache_t *cache = mem_cache_create(10);
    int data = 123;
    mem_cache_push_back(cache, &data, sizeof(data));
    ck_assert_int_eq(cache->size, 4);
    int pop_data;
    mem_cache_pop_back(cache, &pop_data, sizeof(pop_data));
    ck_assert_int_eq(pop_data, 123);
    ck_assert_int_eq(cache->size, 0);
    mem_cache_destroy(cache);
}
END_TEST

Suite* cache_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Cache");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_mem_cache_create);
    tcase_add_test(tc_core, test_mem_cache_push_and_pop);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = cache_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? 0 : 1;
}