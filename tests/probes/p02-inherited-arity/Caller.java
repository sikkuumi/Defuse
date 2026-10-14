// p02-inherited-arity: Utils declares forShell() with no parameters; the one-argument call runs the inherited forShell(String).
package app;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell(lookup("cmd"));
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
