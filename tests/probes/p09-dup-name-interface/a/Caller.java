// p09-dup-name-interface: Two declarations of app.Utils - a class and an interface - so neither can be chosen.
package app;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
