// p04-static-import-type: A static import brings in a nested class called Utils, which shadows the package's Utils.
package app;
import static other.Outer.Utils;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
