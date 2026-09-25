/*
 * THE TWO-LINE FORM, IN JAVA.
 *
 * See build-then-run.py. The Java coverage note already admitted the signature
 * pass only saw commands "built at the call site"; the single-statement build
 * one line earlier is now followed. StringBuilder chains across several
 * statements are still not, and the note still says so.
 */
public class BuildThenRun {

    void concatThenRun(String name) throws Exception {
        String cmd = "ls -l " + name;
        // EXPECT-SIGNATURE command-injection
        Runtime.getRuntime().exec(cmd);
    }

    void fixed() throws Exception {
        String cmd = "uptime";
        Runtime.getRuntime().exec(cmd);
    }
}
