/*
 * A CLEAN WRITE THAT CERTAINLY RUNS.
 *
 * `bar` starts as the request parameter. The switch is decided - `mode` is 'B'
 * - and nothing in case 'B' can leave before `bar = "safe"`, so by the time the
 * page is written the parameter has been overwritten on every path.
 *
 * Deciding which cases are DEAD is not enough for this. The write in case 'B'
 * still sits inside a switch, and a write inside a switch "might not run" -
 * which keeps the old value alive and reports it as a guess. A case that runs
 * every time the switch does is no more conditional than the body of
 * `if (true)`, and the tracer has to be told so. SwitchOnConstant.java holds
 * the other side: the same shape with a `break` inside an `if` before the
 * write, which must still be reported.
 */
import javax.servlet.http.*;

public class SwitchCertainCase extends HttpServlet {

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String bar = request.getParameter("p");
        char mode = 'B';
        switch (mode) {
            case 'B':
                bar = "safe";
                break;
            default:
                bar = "other";
        }
        response.getWriter().print(bar);
    }
}
