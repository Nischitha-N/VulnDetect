/*
 * Regression Corpus - CWE-134: Format String Vulnerability
 */

#include <stdio.h>

void vulnerable_format_string(char *user_msg) {
    // BAD: Non-literal format string passed directly
    printf(user_msg);
}

void safe_format_string(char *user_msg) {
    // GOOD: Explicit literal format specifier
    printf("%s\n", user_msg);
}
