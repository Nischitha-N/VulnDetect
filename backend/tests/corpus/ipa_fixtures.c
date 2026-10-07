/**
 * VulnDetect Inter-Procedural Analysis Corpus Fixture.
 * Demonstrates cross-function Taint chains, helper-driven UAF, and double frees.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ─── 1. Cross-Function Taint (Source -> Caller -> Sink) ──────────────────────

char *get_input(void) {
    return getenv("CMD");
}

void execute(char *x) {
    system(x);
}

void test_interprocedural_command_injection(void) {
    char *cmd = get_input();
    execute(cmd); // VULNERABLE: get_input() source -> execute() sink
}

// ─── 2. Cross-Function Multi-Hop Chain (A -> B -> C) ─────────────────────────

char *step_a(void) {
    return getenv("MULTI_VAR");
}

char *step_b(void) {
    return step_a();
}

void step_c(char *param) {
    popen(param, "r");
}

void test_multihop_chain(void) {
    char *val = step_b();
    step_c(val); // VULNERABLE: step_a -> step_b -> main -> step_c
}

// ─── 3. Cross-Function Use-After-Free ────────────────────────────────────────

void free_buffer(char *p) {
    free(p);
}

void test_interprocedural_uaf(void) {
    char *p = malloc(10);
    free_buffer(p);
    *p = 1; // VULNERABLE: Inter-procedural UAF
}

// ─── 4. Cross-Function Double Free ───────────────────────────────────────────

void test_interprocedural_double_free(void) {
    char *p = malloc(10);
    free_buffer(p);
    free_buffer(p); // VULNERABLE: Duplicate free via helper
}

// ─── 5. Safe Constant Input to Helper ────────────────────────────────────────

void test_safe_constant_to_helper(void) {
    execute("ls -la"); // SAFE: Literal constant string
}
