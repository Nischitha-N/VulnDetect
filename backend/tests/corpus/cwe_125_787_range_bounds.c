/**
 * VulnDetect Range & Bounds Analysis Corpus Fixture.
 * Demonstrates provably safe, confirmed vulnerable, and uncertain patterns.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ─── 1. Array Bounds Indexing ────────────────────────────────────────────────

void safe_bounded_indexing(int i) {
    int buffer[10];
    if (i >= 0 && i < 10) {
        buffer[i] = 42; // PROVED SAFE by RangeAnalyzer
    }
}

void safe_constant_indexing(void) {
    int buffer[10];
    buffer[0] = 1;  // PROVED SAFE
    buffer[9] = 10; // PROVED SAFE
}

void vulnerable_confirmed_oob(void) {
    int buffer[10];
    buffer[15] = 99; // VULNERABLE: CONFIRMED out of bounds (CWE-787)
}

void vulnerable_negative_index(void) {
    int buffer[10];
    buffer[-2] = 5; // VULNERABLE: CONFIRMED negative index (CWE-129)
}

void vulnerable_loop_off_by_one(void) {
    int buffer[10];
    for (int i = 0; i <= 10; i++) {
        buffer[i] = i; // VULNERABLE: CONFIRMED off-by-one at i=10 (CWE-193)
    }
}

void uncertain_unconstrained_index(int user_index) {
    int buffer[10];
    buffer[user_index] = 100; // UNCERTAIN: NEEDS_REVIEW without prior check (CWE-129)
}

// ─── 2. Memory Transfers ─────────────────────────────────────────────────────

void safe_memcpy_transfer(char *src) {
    char dest[32];
    memcpy(dest, src, 16); // PROVED SAFE: 16 <= 32
}

void vulnerable_memcpy_overflow(char *src) {
    char dest[16];
    memcpy(dest, src, 64); // VULNERABLE: CONFIRMED buffer overflow (CWE-120)
}

// ─── 3. Allocation & Type Conversion ─────────────────────────────────────────

void safe_allocation(void) {
    void *p = malloc(1024); // PROVED SAFE
    if (p) free(p);
}

void vulnerable_negative_allocation(void) {
    void *p = malloc(-20); // VULNERABLE: CONFIRMED negative size (CWE-131)
    if (p) free(p);
}

void vulnerable_signed_to_unsigned(char *src, int len) {
    char dest[64];
    memcpy(dest, src, len); // VULNERABLE: LIKELY signed-to-unsigned conversion hazard (CWE-195)
}
