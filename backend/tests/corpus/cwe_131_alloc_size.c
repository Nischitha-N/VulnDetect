/*
 * Regression Corpus - CWE-131: Incorrect Calculation of Buffer Size
 */

#include <stdlib.h>
#include <string.h>

char *vulnerable_alloc_null_term(const char *str) {
    // BAD: strlen does not include the null-terminator byte (+1)
    char *buf = (char *)malloc(strlen(str));
    if (!buf) return NULL;
    strcpy(buf, str);
    return buf;
}

char *safe_alloc_null_term(const char *str) {
    // GOOD: adds + 1 for null terminator byte
    char *buf = (char *)malloc(strlen(str) + 1);
    if (!buf) return NULL;
    strcpy(buf, str);
    return buf;
}
