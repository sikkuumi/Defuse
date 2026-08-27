import javax.servlet.http.*;

/**
 * The fixture that found the bug, kept as the fixture that keeps it fixed.
 *
 * Written BEFORE touching the engine, to test a hypothesis cheaply. The
 * hypothesis was "the container machinery is broken" and it was wrong: two of
 * these three traced fine on the first run. Only the one with a cast in front
 * of it did not, which pointed at the actual defect in ninety seconds after
 * four benchmark-driven guesses had cost a morning and gained nothing.
 */
public class CastAndContainer extends HttpServlet {

  // A cast changes what the compiler calls a value, not the value. The tracer
  // used to unwrap it by taking the first named child - which is the TYPE NAME
  // `String`, not the expression - and duly reported the word "String" clean.
  public void cast(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("q");
    java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
    map.put("keyA", "a-Value");
    map.put("keyB", param);
    String bar = (String) map.get("keyB");
    // EXPECT-FLOW xss
    response.getWriter().println(bar);
  }

  // The same flow with no cast. This one always worked, and it is here so that
  // a future change cannot fix the cast by breaking the map.
  public void noCast(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("q");
    java.util.HashMap<String, String> map = new java.util.HashMap<String, String>();
    map.put("keyB", param);
    String bar = map.get("keyB");
    // EXPECT-FLOW xss
    response.getWriter().println(bar);
  }

  public void list(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("q");
    java.util.List<String> list = new java.util.ArrayList<String>();
    list.add(param);
    String bar = list.get(0);
    // EXPECT-FLOW xss
    response.getWriter().println(bar);
  }
}
