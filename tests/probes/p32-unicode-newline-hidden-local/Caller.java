// p32-unicode-newline-hidden-local: A \u000a escape in a comment hides a real declaration of a variable named Utils.
package app;
public class Caller {
    void run() throws java.io.IOException {
        // pick the shell\u000a Shell Utils = new Shell();
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
