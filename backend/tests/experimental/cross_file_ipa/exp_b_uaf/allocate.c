/**
 * Experiment B — Cross-File UAF: ALLOCATOR FILE
 * Provides a function that allocates a buffer.
 */

#include <stdlib.h>

char *allocate_buffer(void) {
    return (char *)malloc(32);
}
