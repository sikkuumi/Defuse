/*
 * Its own fixed(Object) returns a literal - but the default fixed(String) it
 * gets from HeldIface is more specific, and that is the one
 * `new HeldImpl().fixed("p")` runs. See LocalObjectHelper.java. No sink here;
 * in safe/, any finding is a failure.
 */
package fixtures.held;

public class HeldImpl implements HeldIface {
    public String fixed(Object key) {
        return "bar";
    }
}
