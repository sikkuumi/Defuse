/*
 * The C half of FolderSoundness.java. `int n = 0;` is the only `=` to n, and
 * scanf() writes the input straight into it through &n. The folder read n as
 * 0, decided `n > 5` was false, and skipped the one arm that puts argv[1] into
 * the command - so this was reported as nothing at all.
 */
#include <stdio.h>
#include <stdlib.h>

void scanned(int argc, char **argv) {
    int n = 0;
    char *cmd = "ls";
    scanf("%d", &n);
    if (n > 5) cmd = argv[1];
    // EXPECT-FLOW command-injection
    system(cmd);
}
