/*
 * A SWITCH WHOSE ANSWER IS WRITTEN IN THE SOURCE.
 *
 *     String guess = "ABC";
 *     char switchTarget = guess.charAt(1);   // always 'B'
 *     switch (switchTarget) { case 'A': bar = param; ... case 'B': bar = "bob"; ... }
 *
 * 299 of BenchmarkJava's test cases are built around this switch, and it was
 * the largest single cause of false positives left: 46 safe cases reported,
 * three of them under the green label. The engine did not know that
 * "ABC".charAt(1) is 'B', so it could not tell which case runs, so it assumed
 * any of them might.
 *
 * The same blindness cost the other direction too. With charAt(2) the tainted
 * case is the one that runs - but the clean writes in the cases that CANNOT run
 * were still read as "maybe this cleans it", so real vulnerabilities were
 * reported as guesses rather than proven.
 *
 * WHAT THE FOLDER NOW DECIDES, and nothing more:
 *   - a character literal is its character code, as Java defines it;
 *   - `s.charAt(i)` where s is a string literal, or a local DECLARED once with
 *     one - a parameter, a field, or a second assignment means "cannot tell";
 *   - which case a decided selector lands on, and how far it falls through:
 *     until a `break` (or return, throw, continue) sits directly in a case.
 *
 * Every doubt keeps the case live. The fences below are the shapes where a
 * too-clever folder would delete a real finding.
 */
import javax.servlet.http.*;

public class SwitchOnConstant extends HttpServlet {

    // ---------------------------------------------------------------- DECIDED

    // The BenchmarkJava shape: only case 'B' runs, and it writes a literal.
    void safeCase(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar;
        String guess = "ABC";
        char switchTarget = guess.charAt(1);
        switch (switchTarget) {
            case 'A':
                bar = param;
                break;
            case 'B':
                bar = "bob";
                break;
            case 'C':
            case 'D':
                bar = param;
                break;
            default:
                bar = "bob's your uncle";
                break;
        }
        // EXPECT-CLEAN sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // charAt(2) is 'C', which falls into 'D': the tainted write runs, and the
    // clean writes in 'B' and default cannot. Proven, not guessed.
    void liveCase(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar;
        String guess = "ABC";
        char switchTarget = guess.charAt(2);
        switch (switchTarget) {
            case 'A':
                bar = param;
                break;
            case 'B':
                bar = "bob";
                break;
            case 'C':
            case 'D':
                bar = param;
                break;
            default:
                bar = "bob's your uncle";
                break;
        }
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // No case matches and there is no default, so NOTHING in the switch runs and
    // the value from before it survives untouched. Reading the two clean writes
    // as "maybe" used to cost this its proof.
    void noCaseRuns(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String bar = request.getParameter("p");
        char mode = 'Z';
        switch (mode) {
            case 'A':
                bar = "a";
                break;
            case 'B':
                bar = "b";
                break;
        }
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // ---------------------------------------------------------------- THE FENCE

    // FALL-THROUGH. 'B' has no break, so 'C' runs after it and the tainted write
    // is the last one. A folder that ran only the matching case would call this
    // clean.
    void fallsThrough(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar;
        String guess = "ABC";
        switch (guess.charAt(1)) {
            case 'B':
                bar = "bob";
            case 'C':
                bar = param;
                break;
            default:
                bar = "safe";
        }
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // A BREAK INSIDE AN IF. Case 'B' runs, but it may leave before its clean
    // write. The write is NOT certain, so the value is still reported - as a
    // guess, because proving it would need the condition.
    void breakInsideIf(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String bar = request.getParameter("p");
        char mode = 'B';
        switch (mode) {
            case 'B':
                if (bar.isEmpty()) break;
                bar = "safe";
                break;
            default:
                bar = "other";
        }
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The same break-inside-an-if, at a sink with no pattern rule behind it, so
    // the ONLY thing that can report it is the tracer keeping the value alive.
    // SwitchCertainCase.java is the same code without the `if (...) break;`,
    // and there the clean write does certainly run.
    void breakBeforeCleanWrite(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String bar = request.getParameter("p");
        char mode = 'B';
        switch (mode) {
            case 'B':
                if (bar.isEmpty()) break;
                bar = "safe";
                break;
            default:
                bar = "other";
        }
        // EXPECT-SIGNATURE xss
        response.getWriter().print(bar);
    }

    // THE SELECTOR IS INPUT. Nothing can be decided, so every case stays live.
    void undecidable(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar;
        switch (param.length()) {
            case 1:
                bar = "one";
                break;
            default:
                bar = param;
        }
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // A STRING THAT IS NOT FIXED. `guess` is declared with a literal and then
    // reassigned, so its first character is not known. Deciding it from the
    // declaration alone would pick case 'A' and call this clean.
    void reassignedGuess(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar;
        String guess = "ABC";
        if (param.length() > 3) guess = "XYZ";
        switch (guess.charAt(0)) {
            case 'A':
                bar = "safe";
                break;
            default:
                bar = param;
        }
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // A PARAMETER IS INPUT, even with a literal-looking name. Only a local
    // declared once with a literal counts as fixed.
    void guessFromCaller(String guess, HttpServletRequest request, java.sql.Statement stmt)
            throws Exception {
        String param = request.getParameter("p");
        String bar;
        switch (guess.charAt(1)) {
            case 'B':
                bar = "safe";
                break;
            default:
                bar = param;
        }
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
