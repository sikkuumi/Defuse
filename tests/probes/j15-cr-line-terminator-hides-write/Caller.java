// j15-cr-line-terminator-hides-write: A lone carriage return ends the comment for javac, so the write after it runs.
// j15: a lone CR ends a // comment for javac (JLS 3.4) but not for the parser, so `cmd = lookup("x");` is a real statement.
package app;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = 1 > 0 ? "ls" : "pwd";
        // normalise the command        cmd = lookup("x");
        // EXPECT command-injection
        Runtime.getRuntime().exec("sh -c " + cmd);
    }
}
