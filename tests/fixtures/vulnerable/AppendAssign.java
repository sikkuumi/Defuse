/*
 * `+=` EXTENDS A VALUE. FOR A LONG TIME IT REPLACED IT.
 *
 * See append-assign.js for the full story. Java matters most of the seven,
 * because this is the shape the canonical SQL injection is written in:
 *
 *     String sql = "SELECT * FROM t WHERE x = '";
 *     sql += request.getParameter("x");
 *     sql += "'";                          // the value was wiped here
 *     stmt.execute(sql);
 *
 * The closing quote is not optional decoration - you cannot write that query
 * without it - so the bug did not just weaken Java SQL detection, it removed
 * it for every developer who builds a statement the normal way.
 *
 * Worth recording: OWASP BenchmarkJava, 2,740 generated cases, scored exactly
 * the same before and after the fix. Its cases do not build strings this way.
 * A hand-written fixture found this on its first run and the corpus never
 * could, which is the argument for keeping both instruments.
 */
import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;

public class AppendAssign {

    /* The canonical shape: opening quote, value, closing quote. */
    void quotedStatement(HttpServletRequest request, Statement stmt) throws Exception {
        String sql = "SELECT * FROM users WHERE name = '";
        sql += request.getParameter("name");
        sql += "'";
        // EXPECT-FLOW sql-injection
        stmt.execute(sql);
    }

    /* The other order, so a half-regression cannot hide. */
    void leadingConstant(HttpServletRequest request) throws Exception {
        String cmd = "ping ";
        cmd += "-c 1 ";
        cmd += request.getParameter("host");
        // EXPECT-FLOW command-injection
        Runtime.getRuntime().exec(cmd);
    }

    /*
     * The over-fix guard. A genuine overwrite must still clear the value; if
     * this is ever reported, clean assignment stopped working everywhere and
     * that is a far worse bug than the one this file guards.
     */
    void realReassignmentStillClears(HttpServletRequest request) throws Exception {
        String cmd = "ping ";
        cmd += request.getParameter("host");
        cmd = "ping -c 1 localhost";
        Runtime.getRuntime().exec(cmd);
    }
}
