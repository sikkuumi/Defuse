/*
 * fixtures.other.Quoter - the one StaticHelperCommand.java imports, and so the
 * one its `Quoter.wrap(...)` runs. It returns a value from `lookup`, defined
 * nowhere in the scan. No sink here; in safe/, any finding is a failure.
 */
package fixtures.other;

public class Quoter {
    public static String wrap(String a) {
        return lookup(a);
    }
}
