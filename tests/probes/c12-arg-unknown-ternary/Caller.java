// c12-arg-unknown-ternary: A shape the constant proof read correctly when it was probed; kept so it stays that way.
package app;
public class Caller {
    void run(boolean b) throws java.io.IOException {
        String cmd = Utils.forShell(b ? "echo" : lookup("v"));
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
