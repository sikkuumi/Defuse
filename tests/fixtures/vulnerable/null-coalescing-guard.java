// A NULL CHECK IS NOT A SANITISER.
//
// `branchAssumed` exists because a clean write inside an if/else cannot be
// proven to happen, so the taint survives but the finding drops to a guess.
// That rule is right, and Django proved it is right. It is also, right now,
// the single largest thing standing between real vulnerabilities and a green
// label: of 644 real vulnerabilities in BenchmarkJava, 320 are found but only
// guessed, and 171 of those were downgraded for an unevaluated branch.
//
// Pulling one of the 171 shows the branch is not a branch worth evaluating:
//
//     String param = request.getParameter("q");   // tainted
//     if (param == null) param = "";              // clean write, conditional
//     String sql = "... '" + param + "'";         // sink
//
// The clean write happens ONLY when `param` is null. The taint exists only
// when it is not. The two cases are disjoint, so the tainted path is not
// assumed - it is the only path there is. Calling it a guess understates what
// the tracer actually knows.
//
// And if `param` really is null, the value reaching the sink is `""`, which
// carries no payload. So the case the rule "loses" by ignoring this branch is
// the case with nothing in it.
//
// THE DIRECTION MATTERS, which is the whole reason this is narrow:
//
//     if (x == null) x = "";     the clean write misses the tainted value.
//                                Nothing was assumed. Proof stands.
//
//     if (x != null) x = "";     the clean write lands EXACTLY on the tainted
//                                value. That really might clean it, and the
//                                finding must stay a guess.
//
// Same two tokens, opposite conclusions. A rule that ignored the operator
// would start claiming proof on paths that genuinely might not run, which is
// the failure this file exists to prevent as much as it exists to fix the
// first case.

import java.io.PrintWriter;
import jakarta.servlet.http.HttpServletRequest;

public class NullCoalescingGuard {

    // ---- THE FIX ----
    //
    // The BenchmarkJava shape, reduced. Guarded by `== null`, writing a
    // constant. The tainted value cannot be the one that gets overwritten.
    public void nullDefaultKeepsProof(HttpServletRequest req, PrintWriter out) {
        String param = req.getParameter("q");
        if (param == null) param = "";
        // EXPECT-FLOW xss
        out.println("<div>" + param + "</div>");
    }

    // The same thing written with the operands the other way round. A rule
    // that only matched `x == null` and not `null == x` would be a rule that
    // works on the benchmark and not on the next codebase.
    public void yodaNullDefaultKeepsProof(HttpServletRequest req, PrintWriter out) {
        String param = req.getParameter("q");
        if (null == param) param = "";
        // EXPECT-FLOW xss
        out.println("<div>" + param + "</div>");
    }

    // ---- THE THREE SHAPES THIS MUST NOT TOUCH ----
    //
    // Inverted test. The clean write happens precisely when the value is
    // present, which is precisely when it is dirty. This one really might be
    // clean at the sink, and must stay a guess.
    public void notNullGuardStaysAGuess(HttpServletRequest req, PrintWriter out) {
        String param = req.getParameter("q");
        if (param != null) param = "safe";
        // EXPECT-SIGNATURE xss
        out.println("<div>" + param + "</div>");
    }

    // The guard tests a DIFFERENT variable. Whether the clean write happens
    // has nothing to do with the tainted value, so nothing is known and the
    // caution must be preserved.
    public void guardOnAnotherVariableStaysAGuess(HttpServletRequest req, PrintWriter out) {
        String other = req.getHeader("h");
        String param = req.getParameter("q");
        if (other == null) param = "safe";
        // EXPECT-SIGNATURE xss
        out.println("<div>" + param + "</div>");
    }

    // An ordinary condition with no null test in it at all - the plain
    // branchAssumed case, left exactly as it was.
    public void ordinaryConditionStaysAGuess(HttpServletRequest req, PrintWriter out) {
        String param = req.getParameter("q");
        if (req.getHeader("mode") != null && req.getHeader("mode").length() > 3) {
            param = "safe";
        }
        // EXPECT-SIGNATURE xss
        out.println("<div>" + param + "</div>");
    }
}
