// j10-folder-anon-inherited-field-shadows-local: The condition `dbg` inside the anonymous class is an inherited field, so the write can run.
// j10: inside the anonymous Flags subclass, `dbg` is the inherited field (true), not the local `dbg = false`, so the write to `cmd` runs.
package app;
public class Caller {
    private static String cmd = "ls";

    void run() throws java.io.IOException {
        boolean dbg = false;
        new Flags() {
            {
                if (dbg) cmd = lookup("x");
            }
        };
        // EXPECT command-injection
        Runtime.getRuntime().exec("sh -c " + cmd);
    }
}
