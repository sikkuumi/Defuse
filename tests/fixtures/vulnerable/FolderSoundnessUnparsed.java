/*
 * CODE THE GRAMMAR CANNOT READ MUST NOT BE READ AS CONSTANT.
 *
 * `(n) = x;` is legal Java - a parenthesised variable is still a variable - and
 * the Java grammar this project parses with cannot read it: it becomes an ERROR
 * node, and the write inside it vanished. The one declaration left looked like
 * the only write, so `n` was 0 and a real injection was dropped with a
 * "provably constant" receipt.
 *
 * A function that did not parse cleanly now has no constants at all. This file
 * is ALLOWED to fail to parse - that is its subject - and the parser-health
 * check in run-tests.ts names it as an expected exception, with this reason.
 * From FolderSoundnessProbe.java's adversarial probe.
 */
import javax.servlet.http.*;

public class FolderSoundnessUnparsed extends HttpServlet {

    void parenAssign(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        int n = 0;
        (n) = param.length();
        String bar = n > 5 ? param : "safe";
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    void charAtParen(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar;
        String guess = "ABC";
        (guess) = "XBC";
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

}
