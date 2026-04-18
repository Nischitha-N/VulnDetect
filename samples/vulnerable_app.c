/*
 * vulnerable_app.c
 * Sample file containing intentional vulnerabilities for testing VulnDetect.
 * DO NOT USE IN PRODUCTION.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Vulnerability 1: gets() ──────────────────────────────────────────────── */
void read_username() {
    char buffer[64];
    printf("Enter your name: ");
    gets(buffer);  /* VULN: no bounds check */
    printf("Hello, %s!\n", buffer);
}

/* ── Vulnerability 2: strcpy() ───────────────────────────────────────────── */
void set_username(char *name) {
    char username[32];
    strcpy(username, name);  /* VULN: src may exceed 32 bytes */
    printf("Username set: %s\n", username);
}

/* ── Vulnerability 3: system() with user input ───────────────────────────── */
void run_command(char *user_input) {
    char cmd[256];
    sprintf(cmd, "echo '%s'", user_input);
    system(user_input);  /* VULN: command injection */
}

/* ── Vulnerability 4: sprintf() ──────────────────────────────────────────── */
void build_query(char *user_id) {
    char query[128];
    sprintf(query, "SELECT * FROM users WHERE id='%s'", user_id);  /* VULN: overflow */
    printf("Query: %s\n", query);
}

/* ── Vulnerability 5: printf format string ───────────────────────────────── */
void display_message(char *msg) {
    /* msg could contain format specifiers like %x, %n */
    printf(msg);  /* VULN: format string attack */
}

/* ── Vulnerability 6: scanf %s ───────────────────────────────────────────── */
void read_password() {
    char password[16];
    printf("Password: ");
    scanf("%s", password);  /* VULN: unbounded read */
    printf("Got: %s\n", password);
}

/* ── Vulnerability 7: unchecked malloc ───────────────────────────────────── */
char *create_buffer(size_t size) {
    char *buf = malloc(size);  /* VULN: no NULL check */
    memset(buf, 0, size);      /* crash if malloc returned NULL */
    return buf;
}

/* ── Global fixed buffers (review required) ──────────────────────────────── */
static char log_buffer[512];
char error_message[256];

int main(int argc, char *argv[]) {
    read_username();

    if (argc > 1) {
        set_username(argv[1]);
        run_command(argv[1]);
        build_query(argv[1]);
        display_message(argv[1]);
    }

    read_password();

    char *tmp = create_buffer(1024);
    free(tmp);

    return 0;
}
