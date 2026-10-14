// p28-bare-call-in-enum: A bare build() inside a nested enum runs the enum's own build().
package app;
public class Caller {
    private static String build(String a) {
        return "sh -c " + a;
    }

    enum Mode {
        FAST;

        String build(String a) {
            return lookup(a);
        }

        void go() throws java.io.IOException {
            String cmd = build("echo");
            // EXPECT command-injection
            Runtime.getRuntime().exec(cmd + "-la");
        }
    }
}
