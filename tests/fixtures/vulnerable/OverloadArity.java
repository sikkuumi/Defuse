/*
 * A ONE-ARGUMENT CALL CANNOT RUN A TWO-PARAMETER JAVA METHOD.
 *
 * The tracer indexes a file's functions by name and keeps the first one it
 * meets, so of these two overloads only render(a, b) is ever indexed. A bare
 * render(param) - no receiver, so no declared type to check - resolved to it
 * anyway: `param` was bound to `a`, the method returned a constant, and the
 * XSS below came back clean.
 *
 * Java, Go and the C family refuse a call with the wrong number of arguments,
 * so there the count alone rules a target out. The right overload is still not
 * reached - the index holds one function per name - so the value is carried
 * past the call with that assumption named in the path. That is a smaller
 * claim than following render(String), and a true one; the old answer was a
 * false one.
 */
import javax.servlet.http.*;

public class OverloadArity extends HttpServlet {

    private String render(String a, String b) {
        return "fixed";
    }

    private String render(String s) {
        return s;
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("p");
        String bar = render(param);
        // EXPECT-FLOW xss
        response.getWriter().print(bar);
    }
}
