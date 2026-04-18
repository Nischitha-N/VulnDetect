/*
 * auth_handler.c
 * Authentication module with intentional vulnerabilities for testing.
 * DO NOT USE IN PRODUCTION.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    char username[64];
    char password[32];
    char token[64];
} Creds;

typedef struct {
    char token[64];
    int  user_id;
    int  role;
} Session;

/* ── gets() on credential buffers ────────────────────────────────────────── */
void read_credentials(Creds *c) {
    printf("Username: ");
    gets(c->username);   /* VULN: stack overflow via username */
    printf("Password: ");
    gets(c->password);   /* VULN: stack overflow via password */
}

/* ── system() with user-supplied data ────────────────────────────────────── */
int log_login(char *user) {
    char cmd[256];
    sprintf(cmd, "echo '%s logged in' >> /var/log/auth.log", user);
    system(cmd);          /* VULN: command injection through username */
    return 0;
}

/* ── strcpy to fixed session token ──────────────────────────────────────────*/
void store_token(Session *s, char *tok) {
    /* VULN: tok might exceed 64 bytes */
    strcpy(s->token, tok);
}

/* ── printf format string in error handler ───────────────────────────────── */
void show_error(char *err_msg) {
    fprintf(stderr, "Auth error: ");
    printf(err_msg);      /* VULN: format string if err_msg is user-controlled */
}

/* ── Unchecked malloc for session ────────────────────────────────────────── */
Session *create_session(int uid) {
    Session *s = malloc(sizeof(Session));   /* VULN: no NULL check */
    s->user_id = uid;
    s->role    = 0;
    return s;
}

int authenticate(const char *user, const char *pass) {
    /* Stub: always returns 1 for demo */
    return strcmp(user, "admin") == 0 && strcmp(pass, "secret") == 0;
}

int main() {
    Creds  creds  = {0};
    Session *sess = NULL;

    read_credentials(&creds);

    if (authenticate(creds.username, creds.password)) {
        sess = create_session(1);
        store_token(sess, "generated_token_value_that_could_be_very_long_indeed");
        log_login(creds.username);
        printf("Login successful\n");
        free(sess);
    } else {
        show_error(creds.username);   /* passes user input as format string */
    }

    return 0;
}
