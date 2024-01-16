#include <check.h>
#include "log.h"
#include "page.h"
#include "pgtable.h"
#include "mm.h"

#include <stdio.h>
#include <fcntl.h>

// Define the test suite
START_TEST(test_alloc)
{
    int rc;
    struct page *page, *pages[512];
    struct vmpl_mm_t mm;

    log_init();
    dune_fd = open("/dev/vmpl", O_RDWR);
    ck_assert_msg(dune_fd >= 0, "Failed to open /dev/vmpl");

    // Initialize VMPL-VM
    rc = vmpl_mm_init(&mm);
    ck_assert_msg(rc == 0, "Failed to initialize VMPL-VM");

    // Test vmpl page allocation
    printf("Opened /dev/vmpl\n");
    page = vmpl_page_alloc(dune_fd);
    ck_assert_msg(page != NULL, "Failed to allocate vmpl page");

    vmpl_page_get(page);
    printf("Allocated page at %p\n", page);
    vmpl_page_put(page);
    printf("Freed page\n");

    for (int i = 0; i < 512; i++) {
        // Test dune page allocation
        page = dune_page_alloc(dune_fd);
        ck_assert_msg(page != NULL, "Failed to allocate dune page");

        dune_page_get(page);

        // Test page table
        phys_addr_t pa = dune_page2pa(page);
        virt_addr_t va = pgtable_pa_to_va(pa);
        printf("Page table entry for page at %p: %p\n", page, va);
        sprintf((char *)va, "Hello, world!\n");
        printf("Wrote to page at %p\n", page);
        printf("Contents of page at %p: %s\n", page, (char *)va);

        pages[i] = page;
    }

    for (int i = 0; i < 512; i++) {
        dune_page_put(pages[i]);
    }
}
END_TEST

// Create the test suite
Suite *alloc_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Allocation");

    // Core test case
    tc_core = tcase_create("Core");

    // Add the test case to the suite
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_alloc);

    return s;
}

// Run the tests
int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = alloc_suite();
    sr = srunner_create(s);

    // Run the tests
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? 0 : 1;
}