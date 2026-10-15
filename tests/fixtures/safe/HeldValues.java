/*
 * THE HELPER FILE for LocalObjectHelper.java - an object a caller creates with
 * `new` and then calls, the way BenchmarkJava's 26 remaining SQL decoys use
 * helpers.SeparateClassRequest:
 *
 *     SeparateClassRequest scr = new SeparateClassRequest(request);
 *     String param = scr.getTheValue("BenchmarkTest00930");   // returns "bar"
 *
 * fixed() is that getTheValue(); the rest are the shapes the proof must not
 * read through, each used by a fence in LocalObjectHelper.java. No sink here;
 * in safe/, any finding is a failure.
 */
package fixtures.held;

public class HeldValues {

    private String kept;

    public HeldValues(Object request) {
        this.kept = String.valueOf(request);
    }

    // A literal, whatever the object holds.
    public String fixed(String key) {
        return "bar";
    }

    // Literals around what it is given.
    public String echo(String value) {
        return value + " ";
    }

    // What the constructor stored - which came from outside.
    public String stored() {
        return kept;
    }

    // Two of one name: which runs depends on argument types.
    public String pick(String a, String b) {
        return a + b;
    }

    public String pick(String a, Object b) {
        return lookup(a);
    }
}
