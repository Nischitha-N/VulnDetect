/**
 * VulnDetect Semantic Taint Analysis Corpus Fixtures.
 * Contains direct taint, multi-step propagation, transformations, sanitizers,
 * aliases, struct fields, and safe constant inputs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct UserRequest {
    char username[64];
    char command[256];
};

// Custom unverified sanitizer prototype
void custom_filter(char *input);

// Known sanitizer prototype
char *sanitize_path(const char *path);

// ─── 1. Direct Taint ─────────────────────────────────────────────────────────

void test_direct_taint(void) {
    char *cmd = getenv("USER_CMD");
    system(cmd); // VULNERABLE: Direct getenv() -> system()
}

// ─── 2. Multi-Step Propagation & Transformation ──────────────────────────────

void test_multistep_sprintf(void) {
    char input[128];
    char cmd[256];
    fgets(input, sizeof(input), stdin);
    sprintf(cmd, "echo %s", input);
    popen(cmd, "r"); // VULNERABLE: fgets() -> sprintf() -> popen()
}

// ─── 3. Trusted Sanitizer (Safe) ─────────────────────────────────────────────

void test_trusted_sanitizer_safe(void) {
    char *path = getenv("CONFIG_PATH");
    char *safe_path = sanitize_path(path);
    FILE *f = fopen(safe_path, "r"); // SAFE: Passed through trusted sanitizer
    if (f) fclose(f);
}

// ─── 4. Custom / Unknown Sanitizer (Uncertain) ───────────────────────────────

void test_custom_sanitizer_uncertain(void) {
    char *user_input = getenv("UNTRUSTED");
    custom_filter(user_input);
    system(user_input); // UNCERTAIN: Needs review due to custom unverified sanitizer
}

// ─── 5. Alias Propagation ───────────────────────────────────────────────────

void test_alias_propagation(void) {
    char *orig = getenv("EXEC_NAME");
    char *alias1 = orig;
    char *alias2 = alias1;
    system(alias2); // VULNERABLE: Taint propagated through pointer aliases
}

// ─── 6. Struct Field Propagation ─────────────────────────────────────────────

void test_struct_field_taint(void) {
    struct UserRequest req;
    char *env_val = getenv("REQ_CMD");
    strcpy(req.command, env_val);
    system(req.command); // VULNERABLE: Taint propagated through struct field
}

// ─── 7. Safe Constant Inputs (Safe) ──────────────────────────────────────────

void test_safe_constant_input(void) {
    system("ls -la /tmp"); // SAFE: Constant literal string
    fopen("safe.txt", "r"); // SAFE: Constant literal string
    printf("Static format %d\n", 42); // SAFE: Constant format string
}
