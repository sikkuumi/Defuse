/*
 * The page-writing half of KeyedMapRead.java. BenchmarkJava's XSS cases use the
 * same map, and write `bar` straight to the response - no HTML around it, so no
 * pattern rule speaks, and the only finding was the tracer's: "a value from a
 * collection that took the request parameter reaches the page". The value that
 * comes out is the one put under "keyA-…", a literal. In safe/, any finding is
 * a failure.
 */
import javax.servlet.http.*;

public class KeyedMapReadSafe extends HttpServlet {

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("p");
        String bar = "safe!";
        java.util.HashMap<String, Object> map12345 = new java.util.HashMap<String, Object>();
        map12345.put("keyA-12345", "a-Value");
        map12345.put("keyB-12345", param);
        map12345.put("keyC", "another-Value");
        bar = (String) map12345.get("keyB-12345");
        bar = (String) map12345.get("keyA-12345");

        response.setHeader("X-XSS-Protection", "0");
        response.getWriter().println(bar);
    }
}
