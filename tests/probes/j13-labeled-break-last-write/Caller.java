// j13-labeled-break-last-write: A shape the constant proof read correctly when it was probed; kept so it stays that way.
// j13: `break out` can skip the "ls" write inside the labeled block.
package app;
public class Caller {
    void run(boolean quick) throws java.io.IOException {
        String cmd = lookup("x");
        out: {
            if (quick) break out;
            cmd = "ls";
        }
        // EXPECT command-injection
        Runtime.getRuntime().exec("sh -c " + cmd);
    }
}
