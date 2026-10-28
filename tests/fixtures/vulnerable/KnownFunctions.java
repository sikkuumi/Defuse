import javax.servlet.http.*;

/**
 * WHAT COMMON JAVA METHODS RETURN, so a proof does not rest on a guess.
 *
 * On OWASP BenchmarkJava every proof that rested on an unmodelled method was
 * right - but some were right for the wrong reason. BenchmarkTest00036 writes
 *
 *     response.getWriter().write(param.toCharArray(), 0, length);
 *
 * with `length = param.length()`, and the engine reported TWO paths to that
 * line: one through toCharArray() (the real one) and one through length(),
 * which is an int and cannot carry a script tag anywhere.
 */
public class KnownFunctions extends HttpServlet {

    // The text itself, as characters: still the attacker's.
    public void chars(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("q");
        // EXPECT-FLOW xss
        response.getWriter().write(param.toCharArray(), 0, 10);
    }

    // A new String or StringBuilder made from the value is the value.
    public void wrapped(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("q");
        String bar = new String(new StringBuilder(param).toString());
        // EXPECT-FLOW xss
        response.getWriter().println(bar);
    }

    // A number made from the value is not the value.
    public void length(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("q");
        int n = param.length();
        // EXPECT-CLEAN xss
        response.getWriter().println("Length: " + n);
    }

    // Nor is a true-or-false answer about it.
    public void same(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("q");
        boolean admin = "admin".equals(param);
        // EXPECT-CLEAN xss
        response.getWriter().println("Admin: " + admin);
    }
}
