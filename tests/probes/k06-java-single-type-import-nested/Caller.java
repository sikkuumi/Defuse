// k06-java-single-type-import-nested: A shape the constant proof read correctly when it was probed; kept so it stays that way.
// k06: the single-type import of the nested other.Holder.Utils outranks app.Utils.
package app;
import other.Holder.Utils;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + " -la");
    }
}
