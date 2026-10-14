// p27-bare-call-in-anon-class: A bare build() inside an anonymous class runs the anonymous class's inherited build().
package app;
public class Caller {
    private static String build(String a) {
        return "sh -c " + a;
    }

    void schedule() {
        new Task() {
            void go() throws java.io.IOException {
                String cmd = build("echo");
                // EXPECT command-injection
                Runtime.getRuntime().exec(cmd + "-la");
            }
        }.start();
    }
}
