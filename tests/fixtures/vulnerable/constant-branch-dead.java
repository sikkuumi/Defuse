// TAINT THAT ONLY EVER REACHES A BRANCH THAT CANNOT RUN.
//
// The engine reads statements in order and does not evaluate conditions, so a
// value on the losing side of a decision that was already made at compile time
// is carried anyway. OWASP BenchmarkJava is full of these on purpose - they are
// its trap for scanners that pattern-match without thinking - and they account
// for 128 of the 131 false positives still wearing the proven label.
//
// They are not only a benchmark artefact. Real code has feature flags that are
// permanently off, debug paths behind `if (false)`, and constants that make a
// comparison decidable. Reporting a vulnerability inside dead code is a false
// positive anywhere, not just here.
//
// THE ASSERTION IS "NEVER PROVEN", NOT "NEVER MENTIONED".
//
// This started life in safe/ demanding silence, and silence is the wrong bar.
// The signature pass flags SQL built by concatenation whatever the tracer
// concluded, and that is correct on its own terms - the shape is worth a look.
// What must never happen is the GREEN label: a dead branch cannot support a
// proof, because the path does not execute.
//
// So every case is EXPECT-SIGNATURE. Reported, honestly, without a claim.
//
// EVERY CASE ENDS AT A REAL SINK, and the first draft of this file did not.
// It computed the values and returned them, so it passed instantly and proved
// nothing at all - a safe fixture with no sink in it cannot fail, which makes
// it decoration. The sinks below are the same ones the vulnerable fixtures
// use, so silence here is a statement about the branch and nothing else.

public class ConstantBranchDead {

    // The exact shape BenchmarkJava uses. 126 + 106 = 232, always > 200, so the
    // tainted value is on the side that never runs.
    void ternaryAlwaysTrue(javax.servlet.http.HttpServletRequest request,
                           java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        int num = 106;
        String bar = (7 * 18) + num > 200 ? "constant" : param;
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The same decision spelled the other way round.
    void ternaryAlwaysFalse(javax.servlet.http.HttpServletRequest request,
                            java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar = 1 > 2 ? param : "constant";
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // An if/else where the taint is in the dead arm.
    void ifElseDeadArm(javax.servlet.http.HttpServletRequest request,
                       java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar;
        int num = 106;
        if ((7 * 18) + num > 200) {
            bar = "constant";
        } else {
            bar = param;
        }
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // A literal false guard - the debug path that is never compiled in.
    void neverTaken(javax.servlet.http.HttpServletRequest request,
                    java.sql.Statement stmt) throws Exception {
        String bar = "constant";
        if (false) {
            bar = request.getParameter("p");
        }
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
