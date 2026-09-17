/*
 * FIXTURE: attacker-controlled data reaching an unbounded copy (CWE-120).
 *
 * READ THE LIMITATION BEFORE THE RULE.
 *
 * This is the one C rule where the honesty label has to work hardest, so it is
 * stated here as plainly as it is stated in the report.
 *
 * A buffer overflow is a SIZE bug: it happens when the number of bytes written
 * exceeds the space allocated. Deciding that requires knowing how big the
 * destination is, how long the source is, and whether any pointer in between
 * aliases something else. This engine models NONE of those. It tracks values,
 * not sizes.
 *
 * So what this rule actually claims is narrower, and the wording of the finding
 * says so:
 *
 *     "attacker-controlled data reaches a copy with no length bound"
 *
 * not
 *
 *     "this is a buffer overflow"
 *
 * The first is provable from data flow alone and is what a flow-verified
 * finding here means. The second needs the size analysis we do not have. A
 * `strcpy` into a destination that genuinely is large enough is a FALSE
 * POSITIVE of this rule, and that is declared rather than discovered.
 *
 * It is still worth reporting, because the unbounded functions have no safe
 * upper bound by construction: `strcpy` writes until it meets a NUL byte, and
 * the attacker chooses where that is. The correct versions all take a length.
 *
 * `gets()` is the exception that needs no taint at all - it was removed from
 * the C standard in C11 because there is no way to call it safely. It is
 * reported on sight, as a signature finding, with no flow required.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The classic. The destination is 64 bytes; argv[1] is however long they like. */
void copyTheArgument(int argc, char **argv) {
    char buf[64];
    // EXPECT-FLOW unbounded-copy
    strcpy(buf, argv[1]);
}

/* strcat appends with no bound, so it overflows just as happily. */
void appendTheEnvironment(void) {
    char path[128] = "/var/data/";
    char *suffix = getenv("REPORT_NAME");
    // EXPECT-FLOW unbounded-copy
    strcat(path, suffix);
}

/*
 * sprintf with a %s conversion writes the whole source string regardless of
 * the destination's size. This is the same call that format-string.c reports
 * for a different reason - there, the FORMAT was tainted; here the format is a
 * constant and the tainted value is an argument being written out.
 */
void formatIntoAFixedBuffer(char **argv) {
    char line[80];
    // EXPECT-FLOW unbounded-copy
    sprintf(line, "user=%s", argv[1]);
}

/*
 * gets() cannot be called safely at ALL - it has no length parameter and no
 * way to acquire one. There is no source to trace and none is needed, so this
 * is a signature finding: matched on sight, honestly labelled as unverified
 * flow, because there is no flow to verify.
 */
void theFunctionThatCannotBeUsedSafely(void) {
    char buf[64];
    // EXPECT-SIGNATURE unbounded-copy
    gets(buf);
}

/* Across a function boundary, to prove the value is followed into the copy. */
static void store(char *destination, const char *value) {
    // EXPECT-FLOW unbounded-copy
    strcpy(destination, value);
}

void acrossFunctions(char **argv) {
    char record[32];
    store(record, argv[2]);
}
