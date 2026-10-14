// j05-nested-superclass-bare-call: A NESTED superclass supplies the more specific build(String).
// j05: Runner extends Base, a NESTED class in this file; Base's build(String) is more specific than Runner's own static build(Object).
package app;
public class Caller {
    static class Base {
        String build(String a) { return System.getenv("CMD"); }
    }
    static class Runner extends Base {
        static String build(Object a) { return "sh -c " + a; }
        void run() throws java.io.IOException {
            String cmd = build("echo");
            // EXPECT command-injection
            Runtime.getRuntime().exec(cmd + " -la");
        }
    }
}
