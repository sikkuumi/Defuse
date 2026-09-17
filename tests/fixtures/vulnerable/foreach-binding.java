// FIXTURE: taint does not survive a for-each loop.
//
// Found by diagnosing the 123 remaining BenchmarkJava misses properly, after
// twice categorising them by grepping file text and twice being wrong. Every
// one of the 123 turned out to have the SAME root cause - no source recognised
// at all - and probing the shapes one at a time produced this:
//
//     String[] values = request.getParameterValues("q");
//     out.write(values[0]);              // flow-verified      - indexed works
//     for (String v : values) out.write(v);   // signature only - iteration does not
//
// The engine follows a value into an array and back out by SUBSCRIPT, and then
// loses it the moment somebody iterates instead. That is not a servlet
// problem or a cookie problem, which is what it first looked like: it is every
// for-each in every language, and iterating a collection of attacker-controlled
// values is about as ordinary as code gets.
//
// WHY IT WAS INVISIBLE. The loop node types were already listed in
// CONDITIONAL_NODES - the tracer knew a for-each was a branch, and used that to
// decide a clean write inside one cannot prove a value safe. What nothing did
// was BIND the loop variable: `for (String v : dirty)` introduces `v`, and `v`
// was never entered into the environment, so it evaluated to clean.
//
// Knowing a construct exists and modelling what it does are different things,
// and the first is easy to mistake for the second.

import java.io.IOException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class ForeachBinding {

    // Iterating the source directly.
    public void overACall(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        for (String value : request.getParameterValues("q")) {
            // EXPECT-FLOW xss
            response.getWriter().write("<p>" + value + "</p>");
        }
    }

    // Iterating a variable that holds the source. Same shape, one hop later.
    public void overAVariable(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String[] values = request.getParameterValues("q");
        for (String value : values) {
            // EXPECT-FLOW xss
            response.getWriter().write("<p>" + value + "</p>");
        }
    }

    // The cookie shape, which is what led here. Fourteen BenchmarkJava cases
    // read cookies exactly like this, and every one was missed - not because
    // getCookies() is unknown (it has always been a source) but because the
    // loop threw the taint away.
    public void overCookies(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
            // EXPECT-FLOW xss
            response.getWriter().write("<p>" + cookie.getValue() + "</p>");
        }
    }

    // THE CONTROL. Subscript access already worked and must keep working - if a
    // fix to the loop somehow broke this, the fix is worse than the bug.
    public void indexedStillWorks(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String[] values = request.getParameterValues("q");
        // EXPECT-FLOW xss
        response.getWriter().write("<p>" + values[0] + "</p>");
    }
}
