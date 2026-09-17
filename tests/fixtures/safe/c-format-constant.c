/*
 * FIXTURE: the CORRECT forms must stay silent. EXPECT-NONE.
 *
 * This file is the falsification test for the C rules. Every function below is
 * the fixed version of something in vulnerable/format-string.c, cmdi.c or
 * unbounded-copy.c, and a rule that fires here is punishing the fix - the
 * failure this project treats as worse than a miss, because it teaches people
 * that hardening does not help.
 *
 * The C family makes that trap especially easy to fall into, because in nearly
 * every case the safe call and the dangerous call are THE SAME FUNCTION:
 *
 *     printf(name)         dangerous     printf("%s", name)        safe
 *     strcpy(dst, src)     dangerous     strncpy(dst, src, n)      bounded
 *     sprintf(b, fmt, x)   dangerous     snprintf(b, n, fmt, x)    bounded
 *     system(cmd)          dangerous     execv(path, argv)         no shell
 *
 * A rule keyed on "this function appeared with a tainted value nearby" reports
 * all eight. The distinctions are: WHICH argument is tainted (format string),
 * WHICH function name was used (bounded variants), and whether a shell is
 * involved at all (execv takes an argument vector, so there is no shell to
 * inject into - the argument is a word, never a command).
 *
 * EXPECT-NONE
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

/* The format is a constant. The attacker's string is DATA, not instructions. */
void constantFormat(char **argv) {
    printf("%s", argv[1]);
}

void constantFormatToStream(char **argv) {
    fprintf(stderr, "request from %s\n", argv[1]);
}

void constantFormatToLog(void) {
    char *user = getenv("REMOTE_USER");
    syslog(LOG_INFO, "login attempt by %s", user);
}

/*
 * snprintf takes the destination size, so the write is bounded. The format is
 * still constant, so there is no format-string bug either.
 */
void boundedFormat(char **argv) {
    char out[256];
    snprintf(out, sizeof(out), "hello %s", argv[1]);
}

/*
 * execv takes an argument VECTOR. There is no shell, so there is nothing to
 * inject into - `argv[1]` arrives at the new process as one argument, however
 * many semicolons and backticks it contains. This is the correct fix for the
 * system() calls in cmdi.c and it must not be reported.
 */
void noShellAtAll(char **argv) {
    char *args[] = { "/bin/ping", "-c", "1", argv[1], NULL };
    execv("/bin/ping", args);
}

/* A bounded copy with an explicit length. */
void boundedCopy(char **argv) {
    char buf[64];
    strncpy(buf, argv[1], sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
}

/*
 * A constant command with no interpolation at all. There is no attacker input
 * anywhere in this call, and a rule that fires on the mere presence of
 * `system` would report it.
 */
void constantCommand(void) {
    system("/usr/bin/uptime");
}

/*
 * Constant format, constant everything. Included because an earlier version of
 * the hardcoded-secret rule fired on any string that looked token-shaped, and
 * C is full of long constant strings that are not secrets.
 */
void justAMessage(void) {
    printf("usage: tool [-v] <path>\n");
}
