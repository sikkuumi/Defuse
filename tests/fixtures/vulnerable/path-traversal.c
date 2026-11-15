/*
 * FIXTURE: path traversal (CWE-22) in C.
 *
 * A file name read from a socket is the network's choice: proven. One from
 * argv, the environment or stdin is chosen by whoever runs the program, who
 * could open that file themselves - reported low, to review. It matters when
 * the program has more rights than its caller: setuid, a service, CGI.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

void fromTheSocket(int sock) {
    char name[256];
    recv(sock, name, sizeof(name) - 1, 0);
    // EXPECT-FLOW path-traversal
    FILE *f = fopen(name, "r");
    fclose(f);
}

void fromTheCommandLine(int argc, char **argv) {
    // EXPECT-SIGNATURE path-traversal
    FILE *f = fopen(argv[1], "r");
    fclose(f);
}

void fromTheEnvironment(void) {
    // EXPECT-SIGNATURE path-traversal
    unlink(getenv("LOCK_FILE"));
}
