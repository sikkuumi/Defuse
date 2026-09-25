/*
 * THE SAME CODE, IN A DIFFERENT ORDER, GAVE A DIFFERENT ANSWER.
 *
 * The tracer indexes a file's functions by name, and keeps the FIRST one it
 * meets. It also indexed declarations with no body - an interface method, an
 * abstract method - as if they were functions it could follow a value into.
 *
 * So when an interface sat above its implementation, which is the normal way
 * to write Java, `new Impl().clean(param)` resolved to the interface's
 * `clean(String s);`. There is nothing inside a declaration with no body, so
 * nothing came back out: the value vanished and the XSS below went unreported.
 * Move the interface below the class, and the identical call was
 * flow-verified.
 *
 * A declaration with no body is not a place a value can go. It is no longer
 * indexed, so the real implementation is the one the call reaches.
 *
 * WHY THE SECOND CASE EXISTS. The first case passes even with this fix taken
 * out: the receiver-type check rules the interface method out, and the value is
 * then carried past the call as an assumption - flow-verified, for the wrong
 * reason. A test the fix is not load-bearing for is not a test of the fix. So
 * the second implementation SANITISES, and only a tracer that genuinely reaches
 * its body can see that and prove the line clean.
 */
import javax.servlet.http.*;

public class DeclarationOrder extends HttpServlet {

    interface Cleaner {
        String clean(String s);
    }

    private class Impl implements Cleaner {
        public String clean(String s) {
            return s;
        }
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("p");
        String bar = new Impl().clean(param);
        // EXPECT-FLOW xss
        response.getWriter().print(bar);
    }

    interface Escaper {
        String escape(String s);
    }

    private class HtmlEscaper implements Escaper {
        public String escape(String s) {
            return org.owasp.esapi.ESAPI.encoder().encodeForHTML(s);
        }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("p");
        String bar = new HtmlEscaper().escape(param);
        // EXPECT-CLEAN xss
        response.getWriter().print(bar);
    }
}
