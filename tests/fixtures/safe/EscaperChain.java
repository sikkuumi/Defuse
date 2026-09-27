/*
 * AN ESCAPER WRITTEN AS A CHAIN IS STILL AN ESCAPER.
 *
 * Nothing here is traced from a request - `name` is a plain parameter - so the
 * only rule that can speak is the pattern rule for HTML built by concatenation,
 * and it has to read the escaper to stay quiet. It could not: its name lists
 * allowed a dotted prefix and nothing else, so neither a line break nor the
 * `()` of `encoder()` could be crossed. Both lines below were reported with the
 * sentence "no escaping is visible at this line".
 */
import javax.servlet.http.*;

public class EscaperChain {

    void chainedOverLines(HttpServletResponse response, String name) throws java.io.IOException {
        response.getWriter()
                .println(
                        "<p>Hello "
                                + org.owasp
                                        .esapi
                                        .ESAPI
                                        .encoder()
                                        .encodeForHTML(name)
                                + "</p>");
    }

    void chainedOnOneLine(HttpServletResponse response, String name) throws java.io.IOException {
        response.getWriter().println("<p>Hello " + org.owasp.esapi.ESAPI.encoder().encodeForHTML(name) + "</p>");
    }
}
