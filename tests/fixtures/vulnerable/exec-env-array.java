// FIXTURE: taint reaching a sink through an argument the sink was not reading.
//
// From BenchmarkJava, where roughly fifty scored cases have this shape:
//
//     String[] args    = {cmd};        // the command - not attacker controlled
//     String[] argsEnv = {bar};        // the ENVIRONMENT - carries the taint
//     Runtime r = Runtime.getRuntime();
//     r.exec(args, argsEnv, new java.io.File(System.getProperty("user.dir")));
//
// The engine followed the value correctly all the way to `argsEnv` and then
// stopped, because the `exec` sink declared `argIndexes: [0]` and the payload
// was in position 1.
//
// WHY argIndexes EXISTS AT ALL, so that widening it is not read as "position
// limits were a mistake". They are the single most valuable constraint in the
// SQL sinks: `stmt.execute(query, params)` binds `params` SAFELY, and a sink
// that read every argument would report correct, parameterised code as
// injection - which this project treats as its worst failure. Nothing about
// SQL changes here.
//
// What changes is one Java overload, because of what its arguments MEAN:
//
//     Runtime.exec(String[] cmdarray, String[] envp, File dir)
//                              ^0            ^1        ^2
//
// Position 1 is the environment handed to the new process. An attacker who
// controls it controls LD_PRELOAD, PATH and IFS, which is command execution by
// a slightly longer route. OWASP scores these cases as real vulnerabilities and
// this engine now agrees.
//
// Position 2, the working directory, is deliberately NOT included. Attacker
// control there is a different weakness - it changes where a program runs, not
// what runs - and adding it would be widening on a hunch rather than on the
// meaning of the parameter. Stated here so the omission is a decision rather
// than an oversight.

import java.io.IOException;
import jakarta.servlet.http.HttpServletRequest;

public class ExecEnvArray {

    // The BenchmarkJava shape, reduced. The command is a constant; the
    // environment is the attacker's.
    public void envArrayCarriesTheTaint(HttpServletRequest request) throws IOException {
        String param = request.getHeader("X-Payload");
        String[] args = {"/bin/ls"};
        String[] argsEnv = {param};
        Runtime r = Runtime.getRuntime();
        // EXPECT command-injection
        r.exec(args, argsEnv, new java.io.File(System.getProperty("user.dir")));
    }

    // The two-argument overload, same reasoning, no directory.
    public void twoArgOverload(HttpServletRequest request) throws IOException {
        String param = request.getParameter("q");
        Runtime r = Runtime.getRuntime();
        // EXPECT command-injection
        r.exec(new String[] {"/bin/ls"}, new String[] {param});
    }

    // Position 0 must keep working exactly as before - this is the ordinary
    // case and the one that carried the whole cmdi score until now.
    public void commandItselfIsStillASink(HttpServletRequest request) throws IOException {
        String param = request.getParameter("q");
        Runtime r = Runtime.getRuntime();
        // EXPECT command-injection
        r.exec("ping -c 4 " + param);
    }
}
