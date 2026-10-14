// p22-lambda-body-local: The constant `cmd` is a local inside a lambda; the read outside it is the field.
package app;
public class Caller {
    private String cmd;

    Caller() {
        cmd = lookup("cmd");
    }

    void run() throws java.io.IOException {
        Runnable probe = () -> {
            String cmd = Utils.forShell("echo");
            System.out.println(cmd);
        };
        probe.run();
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
