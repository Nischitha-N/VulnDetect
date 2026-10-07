/*
 * Regression Corpus - CWE-119: Buffer Overflow
 */

#include <stdio.h>
#include <string.h>

void vulnerable_case(const char *src) {
    char dest[16];
    // BAD: Unbounded copy into smaller fixed buffer
    strcpy(dest, src);
}

void safe_case(const char *src) {
    char dest[16];
    // GOOD: Bounded copy with explicit sizeof
    strncpy(dest, src, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0';
}
