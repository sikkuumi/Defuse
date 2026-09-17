// THE FENCE AROUND vulnerable/parameter-names.java.
//
// That change adds `getParameterNames` and `getHeaderNames` to the servlet
// source list, on the reasoning that a client chooses both halves of a query
// string and both halves of a header. The reasoning is sound and it is also
// exactly the kind of reasoning that widens a source list one plausible step at
// a time until half the servlet API is attacker-controlled and the false
// positives are somebody else's problem.
//
// So the boundary is written down: the client picks parameter names and header
// names. THE SERVER picks everything below, and none of them may become sources
// on the strength of looking similar.
//
//   getAttributeNames()   attributes are set by this application's own code,
//                         with setAttribute. A client cannot name one.
//   getServletContext()   deployment configuration.
//   getContextPath()      configured in the container, not sent by anyone -
//                         and already the subject of one flow-verified false
//                         positive on Jenkins. See safe/keyed-container.java.
//   getMethod()           constrained to a fixed set by the servlet container.
//   getProtocol()         likewise.
//   getSession()          the session object, not its contents.
//
// A name ending in "Names" is not the test. WHO CHOOSES IT is the test.
//
// These lines are EXPECT-SIGNATURE rather than EXPECT-NONE, for the same reason
// safe/keyed-container.java is: a pattern matcher looking at
// `write("<p>" + request.getMethod() + "</p>")` sees a method result
// concatenated into HTML and cannot know the container chose it. Flagging that
// unverified is honest. Claiming it as a PROVEN flow from an attacker would not
// be, and that is the assertion this file makes.

import java.io.IOException;
import java.util.Enumeration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class ServerSideNames {

    public void attributesAreOurs(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        // This application called setAttribute earlier. The client had no say.
        Enumeration<String> names = request.getAttributeNames();
        String first = (String) names.nextElement();
        // EXPECT-SIGNATURE xss
        response.getWriter().write("<p>" + first + "</p>");
    }

    public void containerConfiguration(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        // EXPECT-SIGNATURE xss
        response.getWriter().write("<p>" + request.getContextPath() + "</p>");
        // EXPECT-SIGNATURE xss
        response.getWriter().write("<p>" + request.getServletPath() + "</p>");
        // EXPECT-SIGNATURE xss
        response.getWriter().write("<p>" + request.getMethod() + "</p>");
        // EXPECT-SIGNATURE xss
        response.getWriter().write("<p>" + request.getProtocol() + "</p>");
    }
}
