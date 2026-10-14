// j14-this-tostring-concat: `this` is spliced in through toString(), which returns a constructor argument.
// j14: `"ls " + this` splices this.toString(), which returns the target field set from a constructor argument.
package app;
public class Caller {
    private final String target;
    Caller(String target) { this.target = target; }
    @Override public String toString() { return target; }
    void run() throws java.io.IOException {
        // EXPECT command-injection
        Runtime.getRuntime().exec("ls " + this);
    }
}
