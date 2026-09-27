/*
 * THE LAST THREE FALSE POSITIVES UNDER THE GREEN LABEL WERE THIS FILE.
 *
 * BenchmarkJava's flow-verified tier had three mistakes left, and all three
 * were the same code: a helper that switches on "ABC".charAt(1) - always 'B' -
 * where only case 'B' runs and it writes a literal. The tracer could not decide
 * the switch, walked every case, found `bar = param` in cases that can never
 * run, and followed it out of the helper and into the page as PROVEN.
 *
 * A proof built on a case that cannot execute is not a proof. With the switch
 * decided, only case 'B' is walked, `bar` is the literal "bob", and there is
 * nothing to report - which is why this lives in safe/, where any finding at
 * all is a failure.
 */
import javax.servlet.http.*;

public class SwitchDeadHelper extends HttpServlet {

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("p");
        if (param == null) param = "";

        String bar = new Test().doSomething(request, param);

        response.getWriter().print(bar.toCharArray());
    }

    private class Test {

        public String doSomething(HttpServletRequest request, String param) {
            String bar;
            String guess = "ABC";
            char switchTarget = guess.charAt(1);

            switch (switchTarget) {
                case 'A':
                    bar = param;
                    break;
                case 'B':
                    bar = "bob";
                    break;
                case 'C':
                case 'D':
                    bar = param;
                    break;
                default:
                    bar = "bob's your uncle";
                    break;
            }

            return bar;
        }
    }
}
