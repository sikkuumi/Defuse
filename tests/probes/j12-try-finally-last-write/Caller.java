// j12-try-finally-last-write: A shape the constant proof read correctly when it was probed; kept so it stays that way.
// j12: the "ls" write in the try may not run before the finally block reads `cmd`.
package app;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = lookup("x");
        try {
            mayThrow();
            cmd = "ls";
        } finally {
            // EXPECT command-injection
            Runtime.getRuntime().exec("sh -c " + cmd);
        }
    }
}
