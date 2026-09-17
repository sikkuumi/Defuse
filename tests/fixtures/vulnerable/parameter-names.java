// FIXTURE: the parameter NAME is attacker-controlled, not just its value.
//
// Forty-six BenchmarkJava cases read input like this, and every one was missed
// because `getParameterNames()` was not in the source list:
//
//     Enumeration<String> names = request.getParameterNames();
//     while (names.hasMoreElements()) {
//         String name = (String) names.nextElement();
//         String[] values = request.getParameterValues(name);
//         if (values[0].equals("BenchmarkTest00036")) param = name;   // <- the NAME
//     }
//
// WHY THE NAME COUNTS. A client chooses both halves of a query string. Sending
//
//     GET /page?<script>alert(1)</script>=anything
//
// puts markup in the parameter NAME, and a page that echoes the name it found -
// which is exactly what these cases do - is as injectable as one that echoes a
// value. The dictionary already listed getParameter, getParameterValues and
// getParameterMap. It listed the ways of reading what the attacker SENT and
// omitted the way of reading what the attacker CALLED IT.
//
// The same holds for header names, and for the same reason.

import java.io.IOException;
import java.util.Enumeration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class ParameterNames {

    // The BenchmarkJava shape, reduced: iterate the names, keep one, print it.
    public void theNameReachesThePage(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String param = "";
        Enumeration<String> names = request.getParameterNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            if (request.getParameterValues(name) != null) {
                param = name;
            }
        }
        // EXPECT-FLOW xss
        response.getWriter().write("<p>" + param + "</p>");
    }

    // Header names, same reasoning - the client picks them.
    public void headerNamesToo(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        Enumeration<String> names = request.getHeaderNames();
        String first = (String) names.nextElement();
        // EXPECT-FLOW xss
        response.getWriter().write("<p>" + first + "</p>");
    }

    // Reached through the for-each binding added one version earlier, so the
    // two changes are exercised together rather than only in isolation.
    public void iteratedNames(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        for (String name : java.util.Collections.list(request.getParameterNames())) {
            // EXPECT-FLOW xss
            response.getWriter().write("<p>" + name + "</p>");
        }
    }
}
