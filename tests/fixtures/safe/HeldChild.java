/*
 * A class whose own fixed() returns a literal - and which inherits a more
 * specific fixed(String) from HeldBase. See LocalObjectHelper.java. No sink
 * here; in safe/, any finding is a failure.
 */
package fixtures.held;

public class HeldChild extends HeldBase {
    public String fixed(Object key) {
        return "bar";
    }
}
