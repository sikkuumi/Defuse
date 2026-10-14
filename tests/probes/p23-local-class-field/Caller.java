// p23-local-class-field: The constant `cmd` is a field of a local class; the read outside it is the outer field.
package app;
public class Caller {
    private String cmd;

    Caller() {
        cmd = lookup("cmd");
    }

    void run() throws java.io.IOException {
        class Defaults {
            String cmd = Utils.forShell("echo");
        }
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
