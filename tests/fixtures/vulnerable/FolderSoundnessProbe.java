/*
 * THE SECOND ROUND: AN ADVERSARIAL PROBE OF THE CONSTANT FOLDER.
 *
 * After FolderSoundness.java was fixed, the folder was handed to an agent whose
 * only job was to break it: write ordinary-looking code in which a name LOOKS
 * fixed and is not, compile and run it to prove the tainted path executes, and
 * check a control with the condition made opaque. It found 58 such programs in
 * seven languages. Every one was a real injection the engine missed, often with
 * a receipt calling the line "provably constant".
 *
 * These are those programs, one fixture per language, every sink annotated. The
 * causes, and what the folder does about each:
 *   - a write whose target CONTAINS the name - `(n) = x`, `n, err := f()`,
 *     `[n] = [x]`, `list($n) = ...` - was never counted;       -> it now is
 *   - `&(n)`, `&` followed by a comment, a Go pointer-receiver call, a C macro,
 *     a C++ reference
 *     in braces, an atomic store;                                -> writes; and
 *     a C++ local is a constant only if it is `const`/`constexpr`
 *   - `with`, `eval`, `arguments`, `$$x`, extract(), a Python `match` capture;
 *                                                               -> no constants
 *   - octal literals, true division, Python's floor modulo, overflow, unsigned
 *     and narrow types;                                          -> not folded
 *   - a second write deeper than the walk looked (an else-if chain);
 *                                                               -> "cannot tell"
 *   - a GNU `case 1 ... 5` range, and `goto` past a C declaration;
 *                                                               -> not decided
 *   - a function the grammar could not fully parse.             -> no constants
 */
import javax.servlet.http.*;

public class FolderSoundnessProbe extends HttpServlet {

    void octal(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        int n = 010;
        String bar = n < 9 ? param : "safe";
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    void overflow(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        int ttlMillis = 30 * 24 * 60 * 60 * 1000;
        String bar = ttlMillis > 0 ? "safe" : param;
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    void overflowSwitch(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar;
        int mode = 2147483647 + 1;
        switch (mode) {
            case -2147483648:
                bar = param;
                break;
            default:
                bar = "safe";
        }
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
