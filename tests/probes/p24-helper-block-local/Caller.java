// p24-helper-block-local: Inside the helper, the constant `prefix` is a block local; the second return reads the field.
package app;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
