// k07-java-default-package-caller: A shape the constant proof read correctly when it was probed; kept so it stays that way.
// k07: Caller is in the unnamed package; the scan's only Utils is lib.Utils, which `Utils` cannot name here.
public class Caller {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + " -la");
    }
}
