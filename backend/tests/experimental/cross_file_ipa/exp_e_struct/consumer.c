/**
 * Experiment E — Cross-File Struct: CONSUMER FILE
 * Passes struct field value to a dangerous sink.
 */

#include <stdlib.h>
#include "data.h"

void consume(struct Data *d) {
    system(d->value);
}
