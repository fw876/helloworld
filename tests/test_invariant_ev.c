#include <check.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>

/* Declare array_realloc from ev.c */
void *array_realloc(int elem, void *base, int *cur, int cnt);

START_TEST(test_array_realloc_overflow_safety)
{
    /* Invariant: array_realloc must not allocate an undersized buffer
     * when elem * cnt would overflow int arithmetic. Either it must
     * allocate at least elem*cnt bytes or fail safely (return NULL). */

    struct {
        int elem;
        int cnt;
    } cases[] = {
        /* Exploit case: large elem and cnt that overflow when multiplied as int */
        { 65536, INT_MAX / 32 },
        /* Boundary: values just at the edge of overflow */
        { 32768, (INT_MAX / 32768) + 1 },
        /* Valid case: small allocation that should succeed */
        { 16, 64 },
    };
    int num_cases = sizeof(cases) / sizeof(cases[0]);

    for (int i = 0; i < num_cases; i++) {
        int cur = 0;
        int elem = cases[i].elem;
        int cnt = cases[i].cnt;
        int64_t required = (int64_t)elem * (int64_t)cnt;

        void *result = array_realloc(elem, NULL, &cur, cnt);

        if (required > INT_MAX || required < 0) {
            /* Overflow case: must not return a valid undersized buffer */
            /* If it returns non-NULL, cur*elem must cover the request */
            if (result != NULL) {
                int64_t allocated = (int64_t)cur * (int64_t)elem;
                ck_assert_msg(allocated >= required,
                    "Undersized allocation: needed %lld, got %lld (case %d)",
                    (long long)required, (long long)allocated, i);
                free(result);
            }
            /* Returning NULL is acceptable for overflow */
        } else {
            /* Valid case: should succeed with sufficient size */
            ck_assert_ptr_nonnull(result);
            ck_assert_int_ge(cur, cnt);
            free(result);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_array_realloc_overflow_safety);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}