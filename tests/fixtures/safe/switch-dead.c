/*
 * The dead half of switch-constant.c. `mode` is 'B', so case 'A' - the only
 * place argv is read - cannot run, and system() is handed a literal.
 *
 * Before the switch was decided this was reported: the tracer walked case 'A',
 * carried argv[1] into `cmd`, and could only say the clean write in 'B' "might"
 * happen. In safe/, any finding is a failure.
 */
#include <stdlib.h>

void deadCase(int argc, char **argv) {
    char *cmd = "ls";
    char mode = 'B';
    switch (mode) {
    case 'A':
        cmd = argv[1];
        break;
    case 'B':
        cmd = "date";
        break;
    }
    system(cmd);
}
