/**
 * Experiment E — Cross-File Struct: MAIN FILE
 * Creates a Data struct, produces tainted data, then consumes it.
 */

#include <stdlib.h>
#include "data.h"

void produce(struct Data *d);
void consume(struct Data *d);

int main(void) {
    struct Data d;
    produce(&d);
    consume(&d);
    return 0;
}
