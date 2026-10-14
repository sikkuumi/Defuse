// j04-new-x-inherited-member-type: The caller inherits a member class Cmd, which is the one `new Cmd()` creates.
// j04: Caller inherits a member class Cmd from Base, which shadows the top-level Cmd of this file - new Cmd() is Base.Cmd.
package app;
class Cmd {
    String build(String a) { return "sh -c " + a; }
}
public class Caller extends Base {
    void run() throws java.io.IOException {
        String cmd = new Cmd().build("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + " -la");
    }
}
