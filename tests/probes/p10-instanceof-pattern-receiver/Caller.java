// p10-instanceof-pattern-receiver: An instanceof pattern variable named Utils obscures the class.
package app;
public class Caller {
    void run(Object o) throws java.io.IOException {
        if (o instanceof Shell Utils) {
            String cmd = Utils.forShell("echo");
            // EXPECT command-injection
            Runtime.getRuntime().exec(cmd + "-la");
        }
    }
}
