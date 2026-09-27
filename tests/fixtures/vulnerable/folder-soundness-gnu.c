/*
 * GNU's case range, `case 1 ... 5:`. It is a compiler extension, not C, and the
 * grammar reads it as `case 1` followed by an error - so a switch on 3 looked
 * like it matched no case and the value from case 1..5 was dropped.
 *
 * This file is ALLOWED to fail to parse: that is its subject. The parser-health
 * check in run-tests.ts names it as an expected exception, with this reason.
 * A switch whose labels did not parse cleanly is now left undecided.
 */
#include <stdlib.h>

void gnuRange(int argc, char **argv) {
    char *cmd = "ls";
    int mode = 3;
    switch (mode) {
    case 1 ... 5:
        cmd = argv[1];
        break;
    default:
        cmd = "date";
    }
    // EXPECT command-injection
    system(cmd);
}
