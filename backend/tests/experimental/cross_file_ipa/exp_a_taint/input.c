/**
 * Experiment A — Cross-File Taint: SOURCE FILE
 * Provides a function that returns tainted (user-controlled) data.
 */

#include <stdlib.h>

char *get_input(void) {
    return getenv("USER_INPUT");
}
