// p31-unicode-newline-param-write: A \u000a escape in a comment is a real newline to javac: the parameter IS written.
package app;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
