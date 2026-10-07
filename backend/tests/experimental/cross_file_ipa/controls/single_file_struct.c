/**
 * Single-File Control for Experiment E — Struct Field Taint
 * All functions in one translation unit.
 * Expected: VULNERABLE — struct field tainted by getenv, then passed to system().
 */

#include <stdlib.h>

struct Data {
    char *value;
    int len;
};

void produce(struct Data *d) {
    d->value = getenv("TAINTED_VAR");
}

void consume(struct Data *d) {
    system(d->value);
}

int main(void) {
    struct Data d;
    produce(&d);
    consume(&d);
    return 0;
}
