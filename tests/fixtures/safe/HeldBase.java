/*
 * The superclass of HeldChild: its fixed(String) is more specific than the
 * child's own fixed(Object), so it is the one `new HeldChild().fixed("p")`
 * runs - and it returns a value from `lookup`, defined nowhere in the scan. No
 * sink here; in safe/, any finding is a failure.
 */
package fixtures.held;

public class HeldBase {
    public String fixed(String key) {
        return lookup(key);
    }
}
