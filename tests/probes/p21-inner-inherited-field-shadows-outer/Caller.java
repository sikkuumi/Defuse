// p21-inner-inherited-field-shadows-outer: Inside the inner class, an inherited field `cmd` shadows the outer field.
package app;
public class Caller {
    private static final String cmd = Utils.forShell("echo");

    class Worker extends Task {
        void go() throws java.io.IOException {
            // EXPECT command-injection
            Runtime.getRuntime().exec(cmd + "-la");
        }
    }
}
