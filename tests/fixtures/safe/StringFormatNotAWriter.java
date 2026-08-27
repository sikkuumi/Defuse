// EXPECT-NONE
//
// The reason the response sinks are scoped by RECEIVER rather than by argument
// content. Both calls below are `format` on a tainted value; neither writes to
// a page, so neither is XSS.
import javax.servlet.http.*;

public class StringFormatNotAWriter extends HttpServlet {
  public String label(HttpServletRequest request) {
    String param = request.getParameter("q");
    StringBuilder sb = new StringBuilder();
    sb.append(param);
    return String.format("value: %s", param) + sb.toString();
  }
}
