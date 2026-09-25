/*
 * A CALL THAT RESOLVED TO THE WRONG METHOD HID A PROOF, NOT JUST A BUG.
 *
 * Found while accounting for every finding that moved when the arity and
 * receiver-type checks went in: 67 BenchmarkJava XSS guesses disappeared. Every
 * one of them was withdrawn with a sanitiser receipt, and every one deserved to
 * be - each guess named nothing but a call to ESAPI's encodeForHTML(). It was
 * reporting the escaper as the bug.
 *
 * The chain, shown below. A directory search result is written into the page,
 * escaped. Calls are resolved by name, so `idc.search(base, filter, ...)` - a
 * four-argument call on a JNDI directory context - resolved to this file's
 * one-parameter `search(String)`. The value died inside the wrong method, the
 * tracer never reached the page write, and the line fell back to the signature
 * rule, which cannot read an escaper written across several lines.
 *
 * Now the call cannot resolve there - wrong number of arguments, and the
 * receiver is not a Directory - so the value is carried past it as a named
 * assumption, reaches the write, and the tracer sees the escaper and proves the
 * line clean. EXPECT-CLEAN asserts the receipt, not merely the silence.
 *
 * Either check alone is enough to keep this call away from the wrong method, so
 * this file fails only with BOTH taken out. Each one is proven on its own by
 * OverloadArity.java (arity) and ReceiverTypeCaller.java (receiver type).
 */
import javax.servlet.http.*;

public class MisresolvedCallProof extends HttpServlet {

    private static class Directory {
        private boolean search(String person) {
            return person != null;
        }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = request.getParameter("p");
        String filter = "(uid=" + param + ")";
        javax.naming.directory.InitialDirContext idc =
                new javax.naming.directory.InitialDirContext();
        javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
                idc.search("ou=users", filter, new Object[] {}, null);
        while (results.hasMore()) {
            javax.naming.directory.SearchResult sr = results.next();
            // EXPECT-CLEAN xss
            response.getWriter()
                    .println(
                            "<p>Found "
                                    + org.owasp
                                            .esapi
                                            .ESAPI
                                            .encoder()
                                            .encodeForHTML(sr.getName())
                                    + "</p>");
        }
    }
}
