// p26-nested-class-not-in-scope: The file's Cmd is Holder.Cmd, not in scope at the call; the imported Cmd runs.
package app;
import other.Cmd;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = new Cmd().build("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }

    static class Holder {
        static class Cmd {
            String build(String a) { return "sh -c " + a; }
        }
    }
}
