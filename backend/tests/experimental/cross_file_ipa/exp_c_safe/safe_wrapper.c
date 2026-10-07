/**
 * Experiment C — Cross-File Safe: WRAPPER FILE
 * Provides a wrapper that calls system(), but is only called with constants.
 */

#include <stdlib.h>

void safe_wrapper(const char *x) {
    system(x);
}
