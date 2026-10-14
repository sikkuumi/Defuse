// p25-anon-subclass-override: new Cmd(){...} overrides build() in an anonymous subclass.
package app;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = new Cmd() {
            @Override String build(String a) { return lookup(a); }
        }.build("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
class Cmd {
    String build(String a) {
        return "sh -c " + a;
    }
}
