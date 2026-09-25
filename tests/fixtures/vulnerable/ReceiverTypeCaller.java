/*
 * A METHOD CALL ON A `Fragment` CAN ONLY RUN A `Fragment` METHOD.
 *
 * Calls are resolved by name, and across files in the same package the index
 * answers whenever exactly one file declares that name. So
 *
 *     Fragment f = fragment();
 *     String bar = f.renderFragment(param);
 *
 * was followed into ReceiverTypeDecoy.renderFragment() - an unrelated class
 * that happens to share the method name, and returns a hard-coded string. The
 * tracer came back with "clean", and the XSS below was never reported.
 *
 * This was found by accident, which is the worst way: SameNameDelegate.java
 * passed on its own and failed in the suite, because another fixture in the
 * same package declared a doSomething(String). A regression that depends on two
 * unrelated files sharing a name is not a regression test, so this pair exists
 * to make it one on purpose.
 *
 * In Java the receiver's declared type is written down, so a target whose class
 * is not that type is not followed. What happens instead is what happens for
 * any function the tracer cannot see into: the value is carried, and the path
 * says so.
 */
import javax.servlet.http.*;

public abstract class ReceiverTypeCaller extends HttpServlet {

    interface Fragment {
        String renderFragment(String s);
    }

    abstract Fragment fragment();

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("p");
        Fragment f = fragment();
        String bar = f.renderFragment(param);
        // EXPECT-FLOW xss
        response.getWriter().print(bar);
    }
}
