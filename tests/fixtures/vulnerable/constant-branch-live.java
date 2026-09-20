/*
 * THE OTHER HALF OF CONSTANT-BRANCH EVALUATION, AND THE HALF THAT MATTERS MORE.
 *
 * safe/constant-branch-dead.java asserts that taint on an unreachable branch is
 * dropped. On its own that assertion is dangerous: the cheapest way to pass it
 * is to drop taint at every conditional, which would silence most real findings
 * in the suite and score beautifully on the one file that checks.
 *
 * So this file is the fence. Every case here has attacker data on a branch that
 * REALLY RUNS, or behind a condition the engine cannot decide, and every one
 * must survive. A constant folder that cannot tell these two files apart is
 * worse than no constant folder at all - it would be trading false positives
 * for the failure mode that actually gets somebody hacked.
 */
public class ConstantBranchLive {

    // The constant decision lands on the TAINTED side.
    String ternaryPicksTheTaint(javax.servlet.http.HttpServletRequest request,
                                java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        int num = 106;
        String bar = (7 * 18) + num > 200 ? param : "constant";
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
        return bar;
    }

    // An if/else whose LIVE arm carries the value.
    String ifElseLiveArm(javax.servlet.http.HttpServletRequest request,
                         java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar;
        if (1 < 2) {
            bar = param;
        } else {
            bar = "constant";
        }
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
        return bar;
    }

    // A condition the engine CANNOT decide. This is the common case in real
    // code and it must keep behaving exactly as it did before: the value is
    // carried, because refusing to guess means assuming the branch may run.
    String undecidableCondition(javax.servlet.http.HttpServletRequest request,
                                java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar = "constant";
        if (request.getParameter("mode").equals("raw")) {
            bar = param;
        }
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
        return bar;
    }

    // A constant that is NOT decidable by arithmetic alone - a method call on a
    // literal. Folding this would need a model of String, which is exactly the
    // kind of creeping cleverness that turns a folder into a liability.
    String notFoldable(javax.servlet.http.HttpServletRequest request,
                       java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar = "abc".length() > 2 ? param : "constant";
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
        return bar;
    }
}
