// c08-arg-open-field: A shape the constant proof read correctly when it was probed; kept so it stays that way.
package app;
public class Caller {
    static String verb = "echo";
    void run() throws java.io.IOException {
        String cmd = Utils.forShell(verb);
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
