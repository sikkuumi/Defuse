// p20-anon-inherited-field-shadows-local: Inside the anonymous class, an inherited field `cmd` shadows the enclosing local.
package app;
public class Caller {
    void run() {
        String cmd = Utils.forShell("echo");
        new Task() {
            void go() throws java.io.IOException {
                // EXPECT command-injection
                Runtime.getRuntime().exec(cmd + "-la");
            }
        }.start();
    }
}
