/* Vulnerable C sample — DO NOT use in production */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void greet(char *name) {
    char buf[32];
    strcpy(buf, name);  /* buffer overflow */
    printf(name);       /* format string */
}

void run_cmd(char *arg) {
    char cmd[128];
    sprintf(cmd, "ls %s", arg);
    system(cmd);
}

void query_user(char *id) {
    char sql[256];
    sprintf(sql, "SELECT * FROM users WHERE id='%s'", id);
    /* send sql to DB... */
}

int main(int argc, char **argv) {
    if (argc > 1) greet(argv[1]);
    return 0;
}
