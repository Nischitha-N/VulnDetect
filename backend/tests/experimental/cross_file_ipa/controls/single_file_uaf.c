/**
 * Single-File Control for Experiment B — UAF
 * All functions in one translation unit.
 * Expected: VULNERABLE — allocate → release → dereference.
 */

#include <stdlib.h>

char *allocate_buffer(void) {
    return (char *)malloc(32);
}

void release_buffer(char *p) {
    free(p);
}

int main(void) {
    char *p = allocate_buffer();
    release_buffer(p);
    p[0] = 'A';
    return 0;
}
