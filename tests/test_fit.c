#include <assert.h>
#include <stdlib.h>
#include <check.h>

#include "vma.h"

// Create vma dict
dict *create_vma_dict() {
	return rb_dict_new(vmpl_vma_cmp);
}

// Add vma
void add_vma(dict *vma_dict, uint64_t start, uint64_t end) {
	struct vmpl_vma_t *vma = malloc(sizeof(struct vmpl_vma_t));
	vma->start = start;
	vma->end = end;
	dict_insert(vma_dict, vma);
}

// Delete vma dict
void delete_vma_dict(dict *vma_dict) {
	dict_itor *itor = dict_itor_new(vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		vmpl_vma_free(dict_itor_key(itor));
	}
	dict_itor_free(itor);
	dict_free(vma_dict, NULL);
}

// Test cases for FIRST_FIT
START_TEST(test_first_fit)
{
    dict *vma_dict = create_vma_dict();
    fit_algorithm_t first_fit = get_fit_algorithm(FIRST_FIT);
    assert(first_fit(vma_dict, 100, 0, 500) == 0);
    add_vma(vma_dict, 0, 200);
    assert(first_fit(vma_dict, 100, 0, 500) == 200);
    add_vma(vma_dict, 300, 500);
    assert(first_fit(vma_dict, 100, 0, 500) == 200);
    delete_vma_dict(vma_dict);
}
END_TEST

// Test cases for NEXT_FIT
START_TEST(test_next_fit)
{
    dict *vma_dict = create_vma_dict();
    fit_algorithm_t next_fit = get_fit_algorithm(NEXT_FIT);
    assert(next_fit(vma_dict, 100, 0, 500) == 0);
    add_vma(vma_dict, 0, 200);
    assert(next_fit(vma_dict, 100, 0, 500) == 200);
    add_vma(vma_dict, 300, 500);
    assert(next_fit(vma_dict, 100, 0, 500) == 200);
    delete_vma_dict(vma_dict);
}
END_TEST

// Test cases for BEST_FIT
START_TEST(test_best_fit)
{
    dict *vma_dict = create_vma_dict();
    fit_algorithm_t best_fit = get_fit_algorithm(BEST_FIT);
    assert(best_fit(vma_dict, 100, 0, 500) == 0);
    add_vma(vma_dict, 0, 200);
    assert(best_fit(vma_dict, 100, 0, 500) == 200);
    add_vma(vma_dict, 300, 500);
    assert(best_fit(vma_dict, 100, 0, 500) == 200);
    delete_vma_dict(vma_dict);
}
END_TEST

// Test cases for WORST_FIT
START_TEST(test_worst_fit)
{
    dict *vma_dict = create_vma_dict();
    fit_algorithm_t worst_fit = get_fit_algorithm(WORST_FIT);
    assert(worst_fit(vma_dict, 100, 0, 500) == 0);
    add_vma(vma_dict, 0, 200);
    assert(worst_fit(vma_dict, 100, 0, 500) == 200);
    add_vma(vma_dict, 300, 500);
    assert(worst_fit(vma_dict, 100, 0, 500) == 200);
    delete_vma_dict(vma_dict);
}
END_TEST

// Test cases for RANDOM_FIT
START_TEST(test_random_fit)
{
    dict *vma_dict = create_vma_dict();
    fit_algorithm_t random_fit = get_fit_algorithm(RANDOM_FIT);
    assert(random_fit(vma_dict, 100, 0, 500) == 0);
    add_vma(vma_dict, 0, 200);
    assert(random_fit(vma_dict, 100, 0, 500) == 200);
    add_vma(vma_dict, 300, 500);
    assert(random_fit(vma_dict, 100, 0, 500) == 200);
    delete_vma_dict(vma_dict);
}
END_TEST

int main(int argc, char *argv[])
{
    Suite *s = suite_create("test_fit");
    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_first_fit);
    tcase_add_test(tc_core, test_next_fit);
    tcase_add_test(tc_core, test_best_fit);
    tcase_add_test(tc_core, test_worst_fit);
    tcase_add_test(tc_core, test_random_fit);
    suite_add_tcase(s, tc_core);

    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return number_failed;
}