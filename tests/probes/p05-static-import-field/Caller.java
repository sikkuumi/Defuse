// p05-static-import-field: A static import brings in a FIELD called Utils, which obscures the class.
package app;
import static other.Holder.Utils;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
