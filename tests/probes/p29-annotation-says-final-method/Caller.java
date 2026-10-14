// p29-annotation-says-final-method: The word final appears only in an annotation; a subclass overrides build().
package app;
public class Caller {
    @SuppressWarnings("final")
    protected String build(String a) {
        return "sh -c " + a;
    }

    void run() throws java.io.IOException {
        String cmd = build("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
