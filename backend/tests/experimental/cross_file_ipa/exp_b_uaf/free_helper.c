/**
 * Experiment B — Cross-File UAF: FREE HELPER FILE
 * Provides a function that frees a buffer.
 */

#include <stdlib.h>

void release_buffer(char *p) {
    free(p);
}
