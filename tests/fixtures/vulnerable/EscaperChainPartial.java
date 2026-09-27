/*
 * HALF ESCAPED IS NOT ESCAPED - AND THE REPORT MUST SAY WHICH HALF.
 *
 * `first` goes through ESAPI's encodeForHTML; `second` goes in raw. The line is
 * reported, correctly. What was wrong was the sentence: it listed BOTH values
 * and said "no escaping is visible", which is false about the first and sends
 * the reader to fix code that is already right. The test suite checks the
 * wording of this finding, not only that it fired.
 */
import javax.servlet.http.*;

public class EscaperChainPartial {

    void halfEscaped(HttpServletResponse response, String first, String second)
            throws java.io.IOException {
        // EXPECT-SIGNATURE xss
        response.getWriter().println("<p>" + org.owasp.esapi.ESAPI.encoder().encodeForHTML(first) + "</p><p>" + second + "</p>");
    }
}
