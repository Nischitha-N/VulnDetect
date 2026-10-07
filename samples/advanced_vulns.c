/*
 * advanced_vulns.c
 * Comprehensive test file for advanced VulnDetect analysis.
 * Contains intentional vulnerabilities for:
 *   - Null pointer dereference (CWE-476)
 *   - Use-after-free (CWE-416)
 *   - Double free (CWE-415)
 *   - Integer overflow in allocation (CWE-190)
 *   - Resource leaks (CWE-775/401)
 *   - TOCTOU race condition (CWE-367)
 *   - Uninitialized memory (CWE-457)
 *   - Command injection with taint (CWE-78)
 *   - Path traversal (CWE-22)
 *
 * DO NOT USE IN PRODUCTION.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── 1. Null Pointer Dereference (CWE-476) ──────────────────────── */
void null_deref_unsafe(int n) {
    int *arr = malloc(n * sizeof(int));
    /* BUG: No null check — if malloc fails, arr is NULL */
    arr[0] = 42;
    arr[1] = 100;
    free(arr);
}

void null_deref_safe(int n) {
    int *arr = malloc(n * sizeof(int));
    if (!arr) return;   /* safe: null guard */
    arr[0] = 42;
    free(arr);
}

/* ── 2. Use-After-Free (CWE-416) ────────────────────────────────── */
void use_after_free_basic() {
    char *buf = malloc(64);
    if (!buf) return;
    strcpy(buf, "hello");
    free(buf);
    /* BUG: Using buf after freeing it */
    printf("%s\n", buf);
}

void use_after_free_alias() {
    char *original = malloc(128);
    if (!original) return;
    char *alias = original;
    free(original);
    /* BUG: alias points to freed memory */
    alias[0] = 'x';
}

/* ── 3. Double Free (CWE-415) ───────────────────────────────────── */
void double_free_basic() {
    char *p = malloc(32);
    if (!p) return;
    free(p);
    free(p);  /* BUG: double free */
}

void double_free_safe() {
    char *p = malloc(32);
    if (!p) return;
    free(p);
    p = NULL;  /* safe: set to NULL after free */
    free(p);   /* safe: free(NULL) is defined as no-op */
}

/* ── 4. Integer Overflow in Allocation (CWE-190) ────────────────── */
void int_overflow_alloc(int count) {
    /* BUG: count * sizeof(int) can overflow if count is large */
    int *data = malloc(count * sizeof(int));
    if (!data) return;
    data[0] = 1;
    free(data);
}

void int_overflow_calloc(size_t num_items) {
    /* calloc with user-controlled count — potential overflow */
    struct { char name[64]; int id; } *items = calloc(num_items, sizeof(*items));
    if (!items) return;
    items[0].id = 1;
    free(items);
}

/* ── 5. Resource Leak (CWE-775) ─────────────────────────────────── */
void resource_leak_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return;
    char buf[256];
    fgets(buf, sizeof(buf), f);
    printf("Read: %s\n", buf);
    /* BUG: Missing fclose(f) — file descriptor leaked */
}

void resource_leak_safe(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return;
    char buf[256];
    fgets(buf, sizeof(buf), f);
    fclose(f);  /* safe: resource properly closed */
}

void memory_leak_basic(int size) {
    char *buf = malloc(size);
    if (!buf) return;
    memset(buf, 0, size);
    /* BUG: forgot to free buf */
}

/* ── 6. TOCTOU Race Condition (CWE-367) ─────────────────────────── */
void toctou_file_write(const char *path) {
    /* BUG: access() check then fopen() — window for race */
    if (access(path, W_OK) == 0) {
        FILE *f = fopen(path, "w");
        if (f) {
            fprintf(f, "data\n");
            fclose(f);
        }
    }
}

/* ── 7. Command Injection with Taint Propagation (CWE-78) ──────── */
void cmd_injection_direct(char *user_input) {
    /* BUG: User input directly to system() */
    system(user_input);
}

void cmd_injection_propagated(char *user_input) {
    char cmd[256];
    sprintf(cmd, "grep '%s' /var/log/syslog", user_input);
    /* BUG: cmd contains user data flowing to system() */
    system(cmd);
}

/* ── 8. Path Traversal (CWE-22) ─────────────────────────────────── */
void path_traversal_read(char *filename) {
    /* BUG: filename from user without canonicalization */
    FILE *f = fopen(filename, "r");
    if (!f) return;
    char data[1024];
    fread(data, 1, sizeof(data), f);
    fclose(f);
}

/* ── 9. Allocation-Size Mismatch (CWE-131) ──────────────────────── */
char *alloc_no_null_term(const char *src) {
    /* BUG: strlen without + 1 for null terminator */
    char *copy = malloc(strlen(src));
    if (!copy) return NULL;
    strcpy(copy, src);
    return copy;
}

/* ── 10. Combined: taint → format string → leak ─────────────────── */
void combined_vuln(char *user_msg) {
    char *buf = malloc(256);
    if (!buf) return;
    sprintf(buf, user_msg);  /* format string + taint */
    printf(buf);             /* format string */
    /* memory leak: buf never freed */
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    null_deref_unsafe(10);
    null_deref_safe(10);
    use_after_free_basic();
    use_after_free_alias();
    double_free_basic();
    double_free_safe();
    int_overflow_alloc(atoi(argv[1]));
    resource_leak_file("test.txt");
    resource_leak_safe("test.txt");
    toctou_file_write("/tmp/data");
    cmd_injection_direct(argv[1]);
    cmd_injection_propagated(argv[1]);
    path_traversal_read(argv[1]);

    return 0;
}
