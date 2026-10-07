/*
 * Regression Corpus - CWE-415: Double Free
 */

#include <stdlib.h>

void vulnerable_double_free() {
    char *ptr = (char *)malloc(32);
    if (!ptr) return;
    free(ptr);
    // BAD: repeated free without resetting pointer
    free(ptr);
}

void safe_double_free() {
    char *ptr = (char *)malloc(32);
    if (!ptr) return;
    free(ptr);
    // GOOD: pointer set to NULL before subsequent free
    ptr = NULL;
    free(ptr);
}
