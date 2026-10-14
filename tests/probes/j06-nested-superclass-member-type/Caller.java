// j06-nested-superclass-member-type: A nested superclass from another file supplies a member class Utils.
// j06: Caller extends Base, a nested class imported by single-type import; Base's member class Utils shadows app.Utils.
package app;
import other.Holder.Base;
public class Caller extends Base {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + " -la");
    }
}
