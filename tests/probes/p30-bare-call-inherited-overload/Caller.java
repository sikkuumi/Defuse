// p30-bare-call-inherited-overload: An inherited build(String) is more specific than the class's own build(Object).
package app;
public class Caller extends Base {
    private static String build(Object a) {
        return "sh -c " + a;
    }

    void run() throws java.io.IOException {
        String cmd = build("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
