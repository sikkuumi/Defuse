/*
 * The other fixtures.dup.DupStrings - see safe/DupStrings.java. This one hands
 * back a value from `lookup`, which is defined nowhere in the scan.
 */
package fixtures.dup;

public class DupStrings {
    public static String forShell(String append) {
        return lookup(append);
    }
}
