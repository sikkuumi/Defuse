// j09-folder-record-component-shadows-local: The condition `dbg` inside the record's constructor is its component, not the outer local, so the write can run.
// j09: in the local record's compact constructor, `dbg` is the record component (= flag), not the local `dbg = false`, so the write to `cmd` can run.
package app;
public class Caller {
    private static String cmd = "ls";

    void run(boolean flag) throws java.io.IOException {
        boolean dbg = false;
        record Probe(boolean dbg) {
            Probe {
                if (dbg) cmd = lookup("x");
            }
        }
        new Probe(flag);
        // EXPECT command-injection
        Runtime.getRuntime().exec("sh -c " + cmd);
    }
}
