/**
 * Experiment A — Cross-File Taint: SINK FILE
 * Provides a wrapper that passes its argument to system().
 */

#include <stdlib.h>

void wrapper(char *x) {
    system(x);
}
