/*
 * ONE OF TWO CLASSES WITH THE SAME FULL NAME. vulnerable/DupStrings.java is the
 * other, and its forShell() returns something unknown. Which one a build puts
 * on the classpath is not in the source, so a call to fixtures.dup.DupStrings
 * must not be read through either of them. No sink here; in safe/, any finding
 * is a failure.
 */
package fixtures.dup;

public class DupStrings {
    public static String forShell(String append) {
        return "cmd.exe /c " + append;
    }
}
