// j08b-object-noarg-tostring: As j08 with no constructor argument: the object's toString() returns anything.
// j08b: `new Arg()` spliced in with no arguments; Arg.toString() returns an env value.
package app;
class Arg {
    @Override public String toString() { return System.getenv("TARGET"); }
}
public class Caller {
    void run() throws java.io.IOException {
        // EXPECT command-injection
        Runtime.getRuntime().exec("ls " + new Arg());
    }
}
