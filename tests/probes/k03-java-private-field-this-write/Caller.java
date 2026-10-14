// k03-java-private-field-this-write: A shape the constant proof read correctly when it was probed; kept so it stays that way.
// k03: configure() writes the private field through `this.`.
package app;
public class Caller {
    private String cmd = 1 > 0 ? "ls" : "pwd";
    void configure(String c) { this.cmd = c; }
    void run() throws java.io.IOException {
        // EXPECT command-injection
        Runtime.getRuntime().exec("sh -c " + cmd);
    }
}
