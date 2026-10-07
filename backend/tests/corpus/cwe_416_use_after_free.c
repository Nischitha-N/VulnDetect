/*
 * Regression Corpus - CWE-416: Use-After-Free
 */

#include <stdio.h>
#include <stdlib.h>

void vulnerable_uaf() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    free(buf);
    // BAD: reading from freed pointer
    printf("%c\n", buf[0]);
}

void safe_uaf() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    buf[0] = 'Z';
    // GOOD: use before free
    printf("%c\n", buf[0]);
    free(buf);
}
