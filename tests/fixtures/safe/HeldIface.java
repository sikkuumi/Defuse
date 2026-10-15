/*
 * An interface whose default fixed(String) returns a value from `lookup`,
 * defined nowhere in the scan. HeldImpl implements it; see
 * LocalObjectHelper.java. No sink here; in safe/, any finding is a failure.
 */
package fixtures.held;

public interface HeldIface {
    default String fixed(String key) {
        return lookup(key);
    }
}
