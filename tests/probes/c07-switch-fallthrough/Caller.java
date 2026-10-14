// c07-switch-fallthrough: A shape the constant proof read correctly when it was probed; kept so it stays that way.
package app;
public class Caller {
    void run() throws java.io.IOException {
        int mode = 1;
        String cmd = null;
        switch (mode) {
            case 1: cmd = Utils.forShell("echo");
            case 2: cmd = lookup("cmd"); break;
            default: cmd = "ls";
        }
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
