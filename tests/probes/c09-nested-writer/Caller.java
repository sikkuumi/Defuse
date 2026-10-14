// c09-nested-writer: A shape the constant proof read correctly when it was probed; kept so it stays that way.
package app;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
