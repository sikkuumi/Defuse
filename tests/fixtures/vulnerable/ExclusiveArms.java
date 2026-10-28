import javax.servlet.http.*;

/**
 * A CLEAN WRITE IN THE OTHER ARM OF AN IF/ELSE IS NOT AN ASSUMPTION.
 *
 * The opening of hundreds of BenchmarkJava cases:
 *
 *     if (values != null && values.length > 0) param = values[0];
 *     else param = "";
 *
 * At most one arm runs. After the if/else, every run that took the first arm
 * holds the request value, so the path is proven exactly as a path through any
 * other `if` is. The engine flagged it "a branch this engine does not evaluate"
 * because the clean write came second - and then a guessed hop further on
 * silently erased the flag, which is how those cases were proven at all.
 *
 * Inside the clean arm the value IS clean, and branch-assumed.py (from Django)
 * keeps that half honest. The fences below are the other ways to get it wrong.
 */
public class ExclusiveArms extends HttpServlet {

    // The BenchmarkJava shape. The sink is after the if/else.
    public void ifElse(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] values = request.getParameterValues("q");
        String param;
        if (values != null && values.length > 0) param = values[0];
        else param = "";
        // EXPECT-FLOW xss
        response.getWriter().println(param);
    }

    // Two clean arms after the dirty one.
    public void elseIfChain(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String mode = request.getParameter("mode");
        String param;
        if (mode != null) param = request.getParameter("q");
        else if (request.getParameter("x") != null) param = "x";
        else param = "none";
        // EXPECT-FLOW xss
        response.getWriter().println(param);
    }

    // Escaped in one arm only. This used to print "checked and cleared": the
    // escaped write came last, and the last write won.
    public void escapedInOneArm(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String raw = request.getParameter("q");
        String p;
        if (request.getParameter("plain") != null) p = raw;
        else p = org.apache.commons.text.StringEscapeUtils.escapeHtml4(raw);
        // EXPECT-FLOW xss
        response.getWriter().println(p);
    }

    // ---------------------------------------------------------------- FENCES

    // Escaped in the SAME block as the read: the escape runs whenever the read
    // did, so even after the block this stays cleared. The rule above must not
    // cost it that.
    public void escapedInSameBlock(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String p = "";
        if (request.getParameter("go") != null) {
            p = request.getParameter("q");
            p = org.apache.commons.text.StringEscapeUtils.escapeHtml4(p);
        }
        // EXPECT-CLEAN xss
        response.getWriter().println(p);
    }

    // Escaped inside the branch that checks it, and printed there: inside the
    // block the value is the escaped one. DVWA's sqli/source/impossible.php is
    // this shape (is_numeric, intval, print). Only AFTER the block could the
    // unescaped value arrive - escapedSometimes above.
    public void escapedInsideGuard(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String p = request.getParameter("q");
        if (request.getParameter("safe") != null) {
            p = org.apache.commons.text.StringEscapeUtils.escapeHtml4(p);
            // EXPECT-CLEAN xss
            response.getWriter().println(p);
        }
    }

    // Two reads from a map written more than once, joined: each is a guess
    // about which element came out, so the joined string is a guess too.
    public void joinedContainerReads(HttpServletRequest request, HttpServletResponse response) throws Exception {
        java.util.Map<String, String> m = new java.util.HashMap<String, String>();
        m.put("a", request.getParameter("q"));
        m.put("b", "safe");
        String k1 = request.getHeader("k1");
        String k2 = request.getHeader("k2");
        String both = m.get(k1) + "/" + m.get(k2);

        // EXPECT-SIGNATURE xss
        response.getWriter().println(both);
    }

    // Escaped only sometimes, one statement after the dirty write: whether the
    // escape runs is the branch this engine does not evaluate. Never cleared,
    // never proven.
    public void escapedSometimes(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String p = request.getParameter("q");
        if (request.getParameter("safe") != null) p = org.apache.commons.text.StringEscapeUtils.escapeHtml4(p);

        // EXPECT-SIGNATURE xss
        response.getWriter().println(p);
    }

    // Copied INSIDE the clean arm: `copy` only ever holds the clean value.
    public void copiedInCleanArm(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = "";
        String copy = "";
        if (request.getParameter("a") != null) {
            param = request.getParameter("q");
        } else {
            param = "";
            copy = param;
        }

        // EXPECT-SIGNATURE xss
        response.getWriter().println(copy);
    }

    // A guessed hop must not erase an assumed branch. It did: the hop rebuilt
    // the value field by field and left the flag out.
    public void guessAfterBranch(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("q");
        if (request.getParameter("b") != null) param = "";
        String bar = Mangler.mangle(param);

        // EXPECT-SIGNATURE xss
        response.getWriter().println(bar);
    }

    // Nor may joining it to itself. Two assumed halves make an assumed whole.
    public void joinedAssumed(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("q");
        if (request.getParameter("b") != null) param = "";
        String both = param + "/" + param;

        // EXPECT-SIGNATURE xss
        response.getWriter().println(both);
    }

    // A second, separate if may clear it: that one IS an assumption.
    public void laterSeparateIf(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param;
        if (request.getParameter("a") != null) param = request.getParameter("q");
        else param = "";
        if (request.getParameter("b") != null) param = "";

        // EXPECT-SIGNATURE xss
        response.getWriter().println(param);
    }
}
