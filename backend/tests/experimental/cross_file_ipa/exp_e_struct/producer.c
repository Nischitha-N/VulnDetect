/**
 * Experiment E — Cross-File Struct: PRODUCER FILE
 * Populates a struct field with tainted data.
 */

#include <stdlib.h>
#include "data.h"

void produce(struct Data *d) {
    d->value = getenv("TAINTED_VAR");
}
