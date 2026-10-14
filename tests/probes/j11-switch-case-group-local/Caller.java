// j11-switch-case-group-local: A shape the constant proof read correctly when it was probed; kept so it stays that way.
// j11: a local declared in one case group is in scope in the next; the read in case 2 sees lookup().
package app;
public class Caller {
    private static final String cmd = "ls";
    void run(int k) throws java.io.IOException {
        switch (k) {
            case 1:
                String cmd = "echo";
            case 2:
                cmd = lookup("x");
                // EXPECT command-injection
                Runtime.getRuntime().exec("sh -c " + cmd);
                break;
            default:
                break;
        }
    }
}
