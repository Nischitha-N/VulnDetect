/**
 * Single-File Control for Experiment A — Taint
 * All functions in one translation unit.
 * Expected: VULNERABLE — get_input() source flows to wrapper() → system() sink.
 */

#include <stdlib.h>

char *get_input(void) {
    return getenv("USER_INPUT");
}

void wrapper(char *x) {
    system(x);
}

int main(void) {
    char *x = get_input();
    wrapper(x);
    return 0;
}
