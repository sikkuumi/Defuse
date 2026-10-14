// p03-private-not-accessible: Utils's own forShell is private, so the inherited public one runs.
package app;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
