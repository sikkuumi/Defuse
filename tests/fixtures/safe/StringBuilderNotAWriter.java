// EXPECT-NONE
//
// `append` is a real XSS sink on a servlet writer - response.getWriter()
// .append(userInput) writes straight to the page. It is nothing of the sort on
// a StringBuilder, which is a rope of characters. Before receiver mutation this
// distinction did not matter much; the moment `sb.append(dirty)` became a
// tracked shape, every string-building loop in Java started reporting XSS.
//
// Nothing here reaches a sink, so nothing may be reported.
import javax.servlet.http.*;

public class StringBuilderNotAWriter {
    public String describe(HttpServletRequest request) {
        String param = request.getParameter("name");
        StringBuilder sb = new StringBuilder();
        sb.append("user: ");
        sb.append(param);
        return sb.toString();
    }
}
