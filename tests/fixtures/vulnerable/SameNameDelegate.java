/*
 * ALL 38 OF BENCHMARKJAVA'S MISSED VULNERABILITIES HAD THIS SHAPE.
 *
 * A helper named doSomething() calls thing.doSomething() - a method on a
 * DIFFERENT object, reached through an interface. Calls are resolved by name,
 * so the tracer took it for a call to the helper it was already inside, stopped
 * to avoid recursion, and returned "no taint". The value was declared clean,
 * nothing was reported, and 27 XSS and 11 command injections disappeared.
 *
 * The control proved it before the fix was written: the same code with the
 * helper renamed to transform(), in a file with no other doSomething, was
 * flow-verified. The only difference between a caught vulnerability and a
 * silent one was the spelling of a method name.
 *
 * TWO BUGS, AND THIS FILE HAS ONE CASE FOR EACH.
 *
 * Writing the control INTO this file broke it, and that was the second bug.
 * With a doSomething(request, param) declared here, the renamed helper's
 * one-argument call thing.doSomething(param) resolved - by name - to that
 * two-parameter method. The tainted value landed in `request`, `param` arrived
 * empty, and the flow vanished without any stop being hit at all.
 *
 *   wrongAnswerAtTheStop  - the stop returned "clean". Fixed by making a stop
 *                           keep the value and say where it stopped.
 *   wrongTarget           - a call resolved to a method it cannot possibly be.
 *                           A one-argument call never runs a two-parameter Java
 *                           method; arity is checked where the language enforces it.
 *
 * See stopped-trace.py for why the first is delegation, not a Java quirk.
 */
import javax.servlet.http.*;

public abstract class SameNameDelegate extends HttpServlet {

    interface Thing {
        String doSomething(String i);
    }

    abstract Thing createThing();

    public void wrongAnswerAtTheStop(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("p");
        String bar = new Helper().doSomething(request, param);
        // EXPECT-FLOW xss
        response.getWriter().print(bar);
    }

    private class Helper {
        public String doSomething(HttpServletRequest request, String param) {
            Thing thing = createThing();
            return thing.doSomething(param);
        }
    }

    public void wrongTarget(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("p");
        String bar = new Renamed().transform(request, param);
        // EXPECT-FLOW xss
        response.getWriter().print(bar);
    }

    private class Renamed {
        public String transform(HttpServletRequest request, String param) {
            Thing thing = createThing();
            return thing.doSomething(param);
        }
    }
}
