/**
 * Experiment B — Cross-File UAF: MAIN FILE
 * Allocates via allocate_buffer(), frees via release_buffer(),
 * then dereferences the freed pointer — a Use-After-Free.
 */

#include <stdlib.h>

char *allocate_buffer(void);
void release_buffer(char *p);

int main(void) {
    char *p = allocate_buffer();
    release_buffer(p);
    p[0] = 'A';
    return 0;
}
