// j08-object-ctor-tostring: `new Arg(name)` is spliced in through its toString(), which returns anything.
// j08: `new Arg(name)` is spliced in; only its constructor argument is judged, but the text comes from Arg.toString().
package app;
class Arg {
    private final String n;
    Arg(String n) { this.n = n; }
    @Override public String toString() { return System.getenv(n); }
}
public class Caller {
    void run() throws java.io.IOException {
        String name = "TARGET";
        // EXPECT command-injection
        Runtime.getRuntime().exec("ls " + new Arg(name));
    }
}
