/*
 * A SWITCH ON A CHARACTER CONSTANT, IN C.
 *
 * A char literal in C is an int - 'C' is 67 - so a switch on a local bound
 * once to one is decided at compile time, exactly like Java's. The cases that
 * cannot run are not walked, so their clean writes no longer read as "this
 * might clean the value" and a live flow is proven rather than guessed.
 *
 * C adds a way in that Java does not have: `goto`. A label inside a case can be
 * jumped to from outside the switch, so a case whose value does not match is
 * NOT necessarily dead. Any label inside the switch, and any case label that is
 * not directly in the switch body (Duff's device), means the switch is not
 * decided at all.
 */
#include <stdlib.h>

void liveCase(int argc, char **argv) {
    char *cmd = "ls";
    char mode = 'C';
    switch (mode) {
    case 'A':
        cmd = "true";
        break;
    case 'C':
        cmd = argv[1];
        break;
    default:
        cmd = "date";
    }
    // EXPECT-FLOW command-injection
    system(cmd);
}

/* FALL-THROUGH: 'B' has no break, so 'C' runs after it. */
void fallsThrough(int argc, char **argv) {
    char *cmd = "ls";
    char mode = 'B';
    switch (mode) {
    case 'B':
        cmd = "date";
    case 'C':
        cmd = argv[1];
        break;
    default:
        cmd = "true";
    }
    // EXPECT-FLOW command-injection
    system(cmd);
}

/* THE FENCE: a goto can enter case 'A' even though 'A' does not match. */
void gotoIntoCase(int argc, char **argv) {
    char *cmd = "ls";
    char mode = 'B';
    if (argc > 5) goto inside;
    switch (mode) {
    case 'A':
    inside:
        cmd = argv[1];
        break;
    case 'B':
        cmd = "date";
        break;
    }
    // EXPECT-SIGNATURE command-injection
    system(cmd);
}
