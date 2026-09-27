/*
 * The page-writing half of ListIndexRead.java: BenchmarkJava's XSS cases build
 * the same list and write `bar` straight to the response, with no HTML around
 * it for a pattern rule to read. After remove(0), index 1 is "moresafe". In
 * safe/, any finding is a failure.
 */
import javax.servlet.http.*;

public class ListIndexReadSafe extends HttpServlet {

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("p");
        String bar = "alsosafe";
        if (param != null) {
            java.util.List<String> valuesList = new java.util.ArrayList<String>();
            valuesList.add("safe");
            valuesList.add(param);
            valuesList.add("moresafe");

            valuesList.remove(0);

            bar = valuesList.get(1);
        }

        response.setHeader("X-XSS-Protection", "0");
        response.getWriter().println(bar);
    }
}
