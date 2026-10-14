// p12-enum-constant-receiver: Inside the enum, the constant Utils obscures the class.
package app;
public enum Caller {
    Utils;

    String forShell(String a) {
        return lookup(a);
    }

    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
