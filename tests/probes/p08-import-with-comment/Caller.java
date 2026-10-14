// p08-import-with-comment: A comment inside the import line; the imported Utils outranks the same-package one.
package app;
import /* the shell-quoting one */ other.Utils;
public class Caller {
    void run() throws java.io.IOException {
        String cmd = Utils.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
