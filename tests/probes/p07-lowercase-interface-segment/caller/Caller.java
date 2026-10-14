// p07-lowercase-interface-segment: `app` is an interface in scope, so app.Utils is its nested class, not package app's Utils.
package caller;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = app.Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
