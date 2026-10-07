/**
 * Single-File Control for Experiment C — Safe
 * All functions in one translation unit.
 * Expected: SAFE — constant string passed to system() wrapper.
 */

#include <stdlib.h>

void safe_wrapper(const char *x) {
    system(x);
}

int main(void) {
    safe_wrapper("ls -la");
    return 0;
}
