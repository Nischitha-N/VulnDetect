/**
 * Experiment D — Cross-File Alias: MAIN FILE
 * Allocates a buffer, aliases the pointer, frees via alias,
 * then dereferences the original — an alias-based UAF.
 */

#include <stdlib.h>

void free_alias(char *p);

int main(void) {
    char *p = malloc(32);
    char *q = p;
    free_alias(q);
    p[0] = 'A';
    return 0;
}
