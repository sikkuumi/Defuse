// FIXTURE: the falsification half of safe/jenkins-escapers.java.
//
// That file proves a broad SHAPE rule can recognise an escaper it was never
// told about. This file proves the same rule is not merely "any function with
// `escape` in the name", because that would be a silence, and a silence is the
// one failure mode this tool cannot detect in itself.
//
// Every call below escapes for the WRONG DOMAIN. The value is made safe for a
// shell, or for SQL, or for a URL path segment - and then written into HTML,
// where none of that helps.

import java.io.PrintWriter;

public class WrongDomainEscape {

    // Percent-encoding is not HTML escaping. urlEncode leaves the value safe
    // for a query string and still lets a quote break out of an attribute.
    public void urlEncodeIsNotHtmlEscape(PrintWriter out, String name) {
        // EXPECT xss
        out.println("<a href='" + URLEncoder.encode(name) + "'>x</a>");
    }

    // escapeSql protects the database, not the page. A value can be perfectly
    // safe to concatenate into a query and still carry <script> to the browser.
    public void sqlEscapeIsNotHtmlEscape(PrintWriter out, String name) {
        // EXPECT xss
        out.println("<div>" + StringEscapeUtils.escapeSql(name) + "</div>");
    }

    // And the mirror: an HTML escaper does nothing for a shell. esc.escapeHtml
    // turns `<` into `&lt;` and leaves `;` and `|` untouched.
    public void htmlEscapeIsNotShellEscape(String userDir) throws Exception {
        // EXPECT command-injection
        Runtime r = Runtime.getRuntime();
        r.exec("ls " + StringEscapeUtils.escapeHtml4(userDir));
    }
}
