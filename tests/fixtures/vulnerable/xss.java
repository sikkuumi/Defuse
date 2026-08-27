// FIXTURE: Cross-site scripting, Java servlet.
import java.io.PrintWriter;

public class Greeter {
    public void greet(PrintWriter out, String name) {
        // EXPECT xss
        out.println("<h1>Hello " + name + "</h1>");
    }
}
