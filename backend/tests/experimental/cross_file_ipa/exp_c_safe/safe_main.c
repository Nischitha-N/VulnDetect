/**
 * Experiment C — Cross-File Safe: MAIN FILE
 * Calls safe_wrapper() with a constant string — should NOT be flagged.
 */

void safe_wrapper(const char *x);

int main(void) {
    safe_wrapper("ls -la");
    return 0;
}
