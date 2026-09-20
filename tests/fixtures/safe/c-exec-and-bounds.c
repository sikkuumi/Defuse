/* EXPECT-NONE
 *
 * C had fifteen detections and one negative fixture.
 *
 * That ratio is the wrong way round for a language whose dictionary is built
 * from the shortest, most reused function names in computing. c-format-constant.c
 * covers one shape - a constant format string with attacker data as an argument.
 * This covers the other three things C code does correctly every day, each of
 * which sits one character away from something that genuinely is a bug.
 *
 * The engine's own coverage note is explicit that an unbounded-copy finding
 * claims only that attacker data reached a function that writes until a NUL
 * byte, and does NOT claim the destination is too small. So this file uses the
 * bounded functions throughout. A strcpy into a large buffer would be reported
 * here, and that is a declared and deliberate false positive rather than an
 * oversight - which is exactly why it is not in a file that asserts silence.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---------------------------------------------------------------------------
 * 1. exec with a real program rather than a shell.
 *
 * execv runs one named binary and hands the arguments over as separate
 * strings. There is no command line for a semicolon to break out of. The
 * dictionary only treats the exec family as a command sink when the program
 * being run IS a shell, and this one is not.
 * ------------------------------------------------------------------------ */
void resize_an_image(char **argv) {
    char *args[] = { "/usr/bin/convert", argv[1], "-resize", "50%", "out.png", NULL };
    execv("/usr/bin/convert", args);
}

/* ---------------------------------------------------------------------------
 * 2. A bounded copy into a sized buffer.
 *
 * snprintf is in the sanitiser list because it cannot write past the length it
 * is given. Change it to sprintf and this becomes a finding, which is the
 * whole distinction the rule exists to make.
 * ------------------------------------------------------------------------ */
void greet_the_user(void) {
    const char *name = getenv("USER");
    char line[128];
    snprintf(line, sizeof(line), "hello, %s", name ? name : "stranger");
    fputs(line, stdout);
}

/* ---------------------------------------------------------------------------
 * 3. strncat and strncpy, the bounded siblings.
 * ------------------------------------------------------------------------ */
void build_a_path(char **argv) {
    char path[256];
    strncpy(path, "/var/data/", sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';
    strncat(path, argv[1], sizeof(path) - strlen(path) - 1);
    fputs(path, stdout);
}

/* ---------------------------------------------------------------------------
 * 4. A bound parameter rather than a built statement.
 *
 * The value travels as data. It is never part of the SQL text, so no quoting
 * mistake is possible in principle.
 * ------------------------------------------------------------------------ */
void find_a_user(PGconn *conn, char **argv) {
    const char *values[1] = { argv[1] };
    PQexecParams(conn,
                 "SELECT id FROM users WHERE name = $1",
                 1, NULL, values, NULL, NULL, 0);
}

/* ---------------------------------------------------------------------------
 * 5. Attacker data that reaches no sink at all.
 *
 * A source on its own is not a finding. If this fires, the engine is reporting
 * the existence of input rather than a path to anywhere.
 * ------------------------------------------------------------------------ */
int count_the_argument(char **argv) {
    size_t n = strlen(argv[1]);
    return (int)(n % 10);
}
