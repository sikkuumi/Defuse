// j03-new-x-interface-default-overload: Cmd inherits a more specific default build(String) from an interface.
// j03: Cmd implements Shell, whose default build(String) is more specific than Cmd's own build(Object) - new Cmd().build("echo") runs the default method.
package app;
interface Shell {
    default String build(String a) { return System.getenv("CMD"); }
}
class Cmd implements Shell {
    String build(Object a) { return "sh -c " + a; }
}
public class Caller {
    void run() throws java.io.IOException {
        String cmd = new Cmd().build("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + " -la");
    }
}
