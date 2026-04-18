/*
 * string_utils.cpp
 * String utility module with intentional vulnerabilities for testing.
 * DO NOT USE IN PRODUCTION.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>

/* ── strcat overflow ─────────────────────────────────────────────────────── */
void buildPath(char *path, const char *sub) {
    /* VULN: no space check before concatenation */
    strcat(path, "/");
    strcat(path, sub);
}

/* ── Unchecked malloc ────────────────────────────────────────────────────── */
char *createBuffer(size_t sz) {
    char *buf;
    buf = (char *)malloc(sz);   /* VULN: return value not checked */
    memset(buf, 0, sz);         /* undefined behaviour if NULL */
    return buf;
}

/* ── Double free ─────────────────────────────────────────────────────────── */
void cleanup(char *p, char *q) {
    if (p) free(p);
    if (q) free(q);
    free(p);   /* VULN: double-free on p */
}

/* ── memcpy without bounds check ─────────────────────────────────────────── */
void copyData(char *dst, const char *src, size_t len) {
    /* VULN: len not validated against sizeof(dst) */
    memcpy(dst, src, len);
}

/* ── sprintf in C++ code ─────────────────────────────────────────────────── */
const char *formatVersion(int major, int minor, int patch) {
    static char version[16];
    sprintf(version, "%d.%d.%d", major, minor, patch);  /* VULN: potential overflow */
    return version;
}

int main() {
    char path[32] = "/usr";
    buildPath(path, "a_very_long_subdirectory_name_that_overflows");

    char *buf = createBuffer(256);
    char *extra = createBuffer(128);
    cleanup(buf, extra);

    return 0;
}
