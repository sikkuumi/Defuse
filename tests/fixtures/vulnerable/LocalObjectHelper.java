/*
 * AN OBJECT THE METHOD CREATED ITSELF, CALLED THROUGH A VARIABLE.
 *
 * 26 of BenchmarkJava's remaining SQL false positives take their value from a
 * helper object made one line earlier:
 *
 *     SeparateClassRequest scr = new SeparateClassRequest(request);
 *     String param = scr.getTheValue("BenchmarkTest00930");
 *
 * and getTheValue() returns "bar". The constant proof already read
 * `new X(...).m(...)`, where the class that runs is exact; a variable usually
 * hides that, since it could hold any subclass. Not this one: a local declared
 * with `= new X(...)` and never written again holds an X and nothing else. So
 * the proof now reads through it - when X has no body attached, inherits
 * nothing, and declares one method of that name, the same rules as every
 * other helper (safe/HeldValues.java is the helper).
 *
 * `lookup` and `lookupHolder` are defined nowhere in the scan, so the tracer
 * has no source to follow and the pattern rule is the only thing that speaks.
 */
import javax.servlet.http.*;
import fixtures.held.HeldChild;
import fixtures.held.HeldImpl;
import fixtures.held.HeldValues;

public class LocalObjectHelper extends HttpServlet {

    private HeldValues shared = new HeldValues(null);

    // ---------------------------------------------------------------- RESOLVED

    // The BenchmarkJava shape, by full name: fixed() returns "bar".
    void fullName(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        fixtures.held.HeldValues h = new fixtures.held.HeldValues(request);
        String bar = h.fixed("p");
        // EXPECT-CLEAN sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // Through the import, with a parameter: echo("safe") is literals around "safe".
    void imported(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        HeldValues h = new HeldValues(request);
        String bar = h.echo("safe");
        // EXPECT-CLEAN sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // ---------------------------------------------------------------- THE FENCE

    // Written again: `h` may now hold any subclass, whose fixed() returns anything.
    void reassigned(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        HeldValues h = new HeldValues(request);
        h = lookupHolder();
        String bar = h.fixed("p");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // Created in one branch, fetched in the other.
    void conditional(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        HeldValues h;
        if (request.getParameter("a") != null) h = new HeldValues(request);
        else h = lookupHolder();
        String bar = h.fixed("p");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // A body attached to the `new` is an anonymous subclass that overrides fixed().
    void anonymous(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        HeldValues h = new HeldValues(request) {
            public String fixed(String key) {
                return lookup(key);
            }
        };
        String bar = h.fixed("p");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // stored() returns what the constructor kept from outside.
    void constructorStored(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        HeldValues h = new HeldValues(lookup("x"));
        String bar = h.stored();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // Two methods named pick(); `other` is declared Object, so the one that
    // runs is pick(String, Object), which returns something unknown.
    void overloaded(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        HeldValues h = new HeldValues(request);
        Object other = "x";
        String bar = h.pick("a", other);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // HeldChild inherits a more specific fixed(String) that returns anything.
    void inherited(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        HeldChild c = new HeldChild();
        String bar = c.fixed("p");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // HeldImpl gets a more specific fixed(String) from an interface's default method.
    void interfaceDefault(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        HeldImpl i = new HeldImpl();
        String bar = i.fixed("p");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The argument is not fixed, so neither is what echo() hands back.
    void unknownArgument(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        HeldValues h = new HeldValues(request);
        String bar = h.echo(lookup("x"));
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // A field, not a local: any method of this class can replace it.
    void field(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String bar = shared.fixed("p");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    void replaceShared() {
        shared = lookupHolder();
    }
}
