// p01-inherited-overload: Utils inherits a more specific forShell(String) that returns an unknown value.
package app;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
