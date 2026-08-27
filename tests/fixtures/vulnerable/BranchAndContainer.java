import javax.servlet.http.*;

/**
 * The two shapes that dominated the OWASP benchmark's missed XSS cases.
 * Together they were 100+ real bugs the tracer walked straight past.
 */
public class BranchAndContainer extends HttpServlet {

  // A clean write inside an ELSE cannot prove the value is clean, because the
  // two branches are mutually exclusive and one of them is the attacker's.
  public void branch(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("q");
    String bar;
    if (param.length() > 200) bar = "This should never happen";
    else bar = param;
    // EXPECT-FLOW xss
    response.getWriter().write(bar);
  }

  // A container holding one dirty element is a dirty container.
  public void container(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("q");
    Object[] obj = {"a", param};
    // EXPECT-FLOW xss
    response.getWriter().format("Formatted like: %1$s and %2$s.", obj);
  }
}
