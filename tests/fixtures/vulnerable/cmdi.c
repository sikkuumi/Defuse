/*
 * FIXTURE: command injection in C.
 *
 * WHY C IS DIFFERENT FROM EVERY OTHER LANGUAGE IN THIS PROJECT.
 *
 * In JavaScript, Python, Java, PHP and Go, "attacker-controlled input" arrives
 * through a framework: an HTTP request object, a route parameter, a form field.
 * The taint dictionaries for those languages are mostly lists of framework
 * accessors, and a source is recognised by the SHAPE of the expression.
 *
 * C has no framework. Its sources are the operating system itself:
 *
 *     argv[]        the command line
 *     getenv()      the environment, which a parent process chooses
 *     fgets/scanf   standard input
 *     read/recv     a file descriptor or a socket
 *
 * Those are stable across every C program ever written, which makes the C
 * source list SHORTER and MORE RELIABLE than any of the framework lists. There
 * is no Express-versus-Koa problem here. `argv` is argv.
 *
 * The sinks are equally stable, and equally old:
 *
 *     system()      hands a string to /bin/sh
 *     popen()       the same, with a pipe
 *     execl/execlp  execute, and the `p` variants search PATH
 *
 * None of these has a safe overload to confuse us with. `system()` is a shell,
 * always, and there is no parameterised form of it to mistake for the
 * dangerous one - so the class of false positive that dominates the SQL rules
 * (punishing the correct, bound query) does not exist here at all.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The oldest bug in the book: a command line argument reaching a shell. */
void fromTheCommandLine(int argc, char **argv) {
    char cmd[512];
    sprintf(cmd, "ping -c 1 %s", argv[1]);
    // EXPECT-FLOW command-injection
    system(cmd);
}

/*
 * The environment is attacker-controlled whenever the attacker controls the
 * parent process - which is exactly the situation for a CGI program, a setuid
 * binary, or anything launched by a service manager whose config someone else
 * can write.
 */
void fromTheEnvironment(void) {
    char *host = getenv("TARGET_HOST");
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "traceroute %s", host);
    // EXPECT-FLOW command-injection
    popen(cmd, "r");
}

/* Standard input, through the call every C tutorial recommends. */
void fromStandardInput(void) {
    char line[256];
    fgets(line, sizeof(line), stdin);
    // EXPECT-FLOW command-injection
    system(line);
}

/*
 * execlp searches PATH, so even a "safe-looking" fixed program name is a
 * decision the attacker can influence if they control the environment. Here
 * the ARGUMENT is tainted, which is the simpler bug.
 */
void throughExec(char **argv) {
    // EXPECT-FLOW command-injection
    execlp("sh", "sh", "-c", argv[1], (char *)NULL);
}

/* Across a function boundary, to prove the tracer follows the value. */
static char *buildCommand(const char *host) {
    static char cmd[512];
    snprintf(cmd, sizeof(cmd), "nmap %s", host);
    return cmd;
}

void acrossFunctions(char **argv) {
    // EXPECT-FLOW command-injection
    system(buildCommand(argv[1]));
}
