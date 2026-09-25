/*
 * BUILD THE COMMAND, THEN RUN IT: THE ONLY WAY C CAN WRITE A COMMAND INJECTION.
 *
 * The signature rule for command injection only ever looked INSIDE the shell
 * call's brackets. `os.system("ls " + name)` was reported; the same thing split
 * across two lines was not - in any language. See build-then-run.py.
 *
 * Every other language misses one common shape that way. C misses all of them,
 * because C cannot build a string inside a call's brackets: there is no `+` for
 * strings. A command is always formatted into a buffer first and handed to the
 * shell afterwards, so a signature pass that stops at the brackets sees
 * `system(buf)` - a bare name - and has nothing to say. The coverage note said
 * "implemented" for the whole time that was true.
 *
 * The parameters below are ordinary function parameters, not recognised
 * sources, so the tracer has no source to start from and only the signature
 * pass can speak. That isolates exactly the thing this file is about.
 *
 * THE FORMAT STRING IS A TYPE DECLARATION, AND THE RULE READS IT.
 *
 * `%d` can only ever produce digits and a sign - there is no way for it to emit
 * a semicolon. `%s` and `%c` splice text. So a command formatted from integers
 * alone is not a shape worth flagging, and the fence at the bottom says so.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void list_dir(const char *name) {
    char buf[256];
    snprintf(buf, sizeof buf, "ls -l %s", name);
    // EXPECT-SIGNATURE command-injection
    system(buf);
}

void read_output(const char *host) {
    char cmd[128];
    sprintf(cmd, "ping -c 1 %s", host);
    // EXPECT-SIGNATURE command-injection
    popen(cmd, "r");
}

/* The strcpy-then-strcat idiom: a reset followed by an extension. */
void grep_for(const char *term) {
    char cmd[256];
    strcpy(cmd, "grep -r ");
    /* strcat from a parameter into a fixed buffer is its own finding, and a
     * correct one - a long enough term overruns cmd before the shell ever runs. */
    // EXPECT-SIGNATURE unbounded-copy
    strcat(cmd, term);
    // EXPECT-SIGNATURE command-injection
    system(cmd);
}

/* An initialised buffer, then extended. */
void show(const char *file) {
    char cmd[256] = "cat ";
    // EXPECT-SIGNATURE unbounded-copy
    strcat(cmd, file);
    // EXPECT-SIGNATURE command-injection
    system(cmd);
}

/* ------------------------------------------------------------------ FENCES
 * Every one of these must stay silent. Each is the nearest safe neighbour of a
 * case above, so a rule that simply reports every system(variable) fails here.
 */

/* Integers only: %d cannot carry a shell metacharacter. */
void stop(int pid) {
    char buf[64];
    snprintf(buf, sizeof buf, "kill -9 %d", pid);
    system(buf);
}

/* Built, but only ever from literals. */
void uptime_once(void) {
    char cmd[64];
    strcpy(cmd, "uptime");
    strcat(cmd, " -p");
    system(cmd);
}

/* A pointer to a literal. */
void whoami(void) {
    const char *cmd = "whoami";
    system(cmd);
}

/* A parameter passed straight through: nothing here says how it was built. */
void run_given(const char *cmd) {
    system(cmd);
}
