/**
 * Single-File Control for Experiment D — Alias
 * All functions in one translation unit.
 * Expected: VULNERABLE — alias pointer freed, original dereferenced.
 */

#include <stdlib.h>

void free_alias(char *p) {
    free(p);
}

int main(void) {
    char *p = malloc(32);
    char *q = p;
    free_alias(q);
    p[0] = 'A';
    return 0;
}
