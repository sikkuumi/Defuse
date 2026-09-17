/*
 * FIXTURE: format string vulnerabilities (CWE-134).
 *
 * WHY THIS RULE EXISTS, AND WHY IT IS NEW.
 *
 * Every other rule in this project was written for a bug that exists in most
 * languages. This one is specific to the C family, and it is the single best
 * argument for pointing a taint engine at C at all - because it is a
 * memory-corruption bug that a taint engine catches EXACTLY, with no
 * approximation.
 *
 * The bug:
 *
 *     printf(name);            // name is attacker-controlled
 *
 * looks harmless and is not. printf reads its first argument as a FORMAT
 * STRING, so an attacker who controls it supplies the conversions too:
 *
 *     %x %x %x %x     walks up the stack and prints whatever is there
 *     %s              dereferences a stack value as a pointer - crash or leak
 *     %n              WRITES the number of bytes printed to a pointer argument
 *
 * That last one turns an innocuous logging call into an arbitrary memory
 * write. It is how a format string bug becomes code execution.
 *
 * WHY A TAINT ENGINE IS THE RIGHT TOOL HERE, unlike for most C bugs.
 *
 * A buffer overflow needs the analyser to know how big a buffer is and how
 * many bytes a copy moves. That is a size and aliasing problem, and this
 * engine does not model either - see the memory-safety declaration in the
 * coverage report.
 *
 * A format string bug needs none of that. The question is exactly "is this one
 * argument attacker-controlled?", which is the only question this engine
 * answers. So here a flow-verified finding means what it says.
 *
 * THE FIX, which the safe fixture asserts stays quiet:
 *
 *     printf("%s", name);      // the format is a constant; name is just data
 *
 * Note the shape of that. The dangerous call and the safe call are the SAME
 * FUNCTION with an argument added - exactly like the prepared-statement case
 * in SQL. A rule that fired on "printf with a tainted argument anywhere" would
 * report the fix as the bug, which is the one mistake this project treats as
 * worse than a miss. The sink is argument ZERO only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/* The textbook case: the format argument IS the attacker's string. */
void printfTheInput(int argc, char **argv) {
    // EXPECT-FLOW format-string
    printf(argv[1]);
}

/* fprintf puts the stream first, so the format is argument ONE. */
void fprintfTheInput(char **argv) {
    // EXPECT-FLOW format-string
    fprintf(stderr, argv[1]);
}

/*
 * The most common real-world instance by a distance. Logging a value is such
 * an obviously-harmless thing to do that this survives code review constantly.
 */
void loggingTheInput(void) {
    char *user = getenv("REMOTE_USER");
    // EXPECT-FLOW format-string
    syslog(LOG_INFO, user);
}

/*
 * sprintf is doubly dangerous - a tainted format here is both a format string
 * bug AND an unbounded write into `out`. This fixture asserts the format half;
 * unbounded-copy.c asserts the other.
 */
void sprintfTheInput(char *out, char **argv) {
    // EXPECT-FLOW format-string
    sprintf(out, argv[1]);
}

/* Through a variable and a function, to prove the value is followed. */
static const char *describe(const char *raw) {
    return raw;
}

void acrossFunctions(char **argv) {
    const char *message = describe(argv[2]);
    // EXPECT-FLOW format-string
    printf(message);
}
