/**
 * Experiment A — Cross-File Taint: CALLER / MAIN FILE
 * Connects the source (get_input) to the sink (wrapper).
 */

#include <stdlib.h>

char *get_input(void);
void wrapper(char *x);

int main(void) {
    char *x = get_input();
    wrapper(x);
    return 0;
}
