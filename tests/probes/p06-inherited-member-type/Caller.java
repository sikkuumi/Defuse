// p06-inherited-member-type: The caller inherits a member class called Utils from its superclass.
package app;
public class Caller extends Base {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
