// k04-java-static-call-subclass-name: A shape the constant proof read correctly when it was probed; kept so it stays that way.
// k04: SubUtils hides Utils.forShell with its own static method.
package app;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = SubUtils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + " -la");
    }
}
