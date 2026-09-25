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
// THE ASSERTION WAS "NEVER PROVEN". IT IS NOW "PROVED CLEAN", AND HERE IS WHY.
//
// This file started life in safe/ demanding silence, and silence was the wrong
// bar: the signature pass flagged SQL built by concatenation whatever the tracer
// concluded, which was correct on its own terms. So every case was annotated
// as a signature guess - reported, honestly, without a claim - and the thing
// that had to never happen was the green label on a branch that does not run.
//
// That was right while the signature rules could not see what the folder saw.
// Once the folder moved out of the tracer (src/taint/fold.ts), the SQL rule
// could ask it the same question, and the honest answer to "is anything
// attacker-controlled spliced into this string?" became NO: every value that
// can reach it is the literal "constant". A guess the engine can disprove is
// not a guess worth printing - that is what retracted(), the function this tool
// is named after, has always done for sanitisers.
//
// So every case is now EXPECT-CLEAN, which is deliberately stronger than
// silence: no finding on the line AND a proved-clean record for it. A rule that
// crashed would also be silent; it would not leave a receipt.
//
// The fence is ConstantProofFence.java, and it matters more than this file.
// Withdrawing a guess is a claim that a line is clean, and a wrong one hides a
// real bug.
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
        // EXPECT-CLEAN sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The same decision spelled the other way round.
    void ternaryAlwaysFalse(javax.servlet.http.HttpServletRequest request,
                            java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar = 1 > 2 ? param : "constant";
        // EXPECT-CLEAN sql-injection
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
        // EXPECT-CLEAN sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // A literal false guard - the debug path that is never compiled in.
    void neverTaken(javax.servlet.http.HttpServletRequest request,
                    java.sql.Statement stmt) throws Exception {
        String bar = "constant";
        if (false) {
            bar = request.getParameter("p");
        }
        // EXPECT-CLEAN sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
