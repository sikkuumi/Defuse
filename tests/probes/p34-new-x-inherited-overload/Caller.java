// p34-new-x-inherited-overload: Cmd inherits build(String) from Base, which is more specific than its own build(Object) - so new Cmd().build("echo") runs the inherited one.
package app;
public class Caller {
    static class Base {
        String build(String a) {
            return lookup(a);
        }
    }

    static class Cmd extends Base {
        String build(Object a) {
            return "sh -c " + a;
        }
    }

    void run() throws java.io.IOException {
        String cmd = new Cmd().build("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
