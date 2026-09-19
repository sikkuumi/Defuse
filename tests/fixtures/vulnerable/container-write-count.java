// HOW MANY THINGS WERE IN THE BOX?
//
// `keyed-container.java` settled that taint lands on a container as a whole and
// that narrowing it is dangerous. This file is not about narrowing taint. Every
// line below still reports. It is about which of those reports may call itself
// PROVEN.
//
// The tracer records the write honestly already - the flow path literally says
// "collected into `list` via `add()`" and the coverage note says we taint the
// container whole, not per element. It writes the imprecision down and then
// labels the finding flow-verified anyway. The admission and the claim
// contradict each other in the same report.
//
// MEASURED, on OWASP BenchmarkJava, flow-verified findings only:
//
//     collected via add()     TP  55   FP  57     49.1%
//     collected via put()     TP  41   FP  36     53.2%
//     no collect step at all  TP 238   FP  95     71.5%
//
// A coin, for a third of the bucket. "I traced this and I am certain" is not a
// sentence you can attach to 49.1%.
//
// THE DISTINCTION THIS FILE EXISTS TO PIN DOWN. It is not "containers are
// unreliable". It is narrower, and the narrowness is the whole point:
//
//   one write        Only one value ever entered. Whatever comes back out is
//                    that value. The trace is sound and stays PROVEN.
//
//   several writes   Several values entered and the engine does not model which
//                    index or key came back. It is guessing which one. Report
//                    it, do not certify it.
//
//   append / insert  NOT a container of separable elements. A StringBuilder IS
//                    its contents - every appended piece is in the result, so
//                    the count is irrelevant and it stays PROVEN however many
//                    times it was written. Excluding these from the rule is
//                    what stops the fix eating real findings.
//
// The failure mode to watch for is the same one keyed-container.java warns
// about, one level up: if this rule is written too broadly it does not silence
// findings, it silences CONFIDENCE, and a scanner whose green label has quietly
// become unreachable is as useless as one that has gone quiet.

import java.io.PrintWriter;
import jakarta.servlet.http.HttpServletRequest;

public class ContainerWriteCount {

    // ---- ONE WRITE: STILL PROVEN ----
    //
    // The same shape as collectionIsTheValue in keyed-container.java, restated
    // here so that a change to the write-count rule cannot pass without this
    // being green. One value went in. It is the one that came out.
    public void oneAddIsProven(HttpServletRequest req, PrintWriter out) {
        java.util.List<String> parts = new java.util.ArrayList<>();
        parts.add(req.getParameter("part"));
        // EXPECT-FLOW xss
        out.println("<div>" + parts.get(0) + "</div>");
    }

    // ---- SEVERAL WRITES: A GUESS ----
    //
    // Three values in, one of them dirty, and the read asks for index 1. The
    // engine does not track indices, so it cannot say which of the three is
    // being printed. It must still report - the dirty value really is in there
    // and really might be printed - but it has not proven anything.
    public void manyAddsIsAGuess(HttpServletRequest req, PrintWriter out) {
        java.util.List<String> values = new java.util.ArrayList<>();
        values.add("safe");
        values.add(req.getParameter("q"));
        values.add("alsosafe");
        // EXPECT-SIGNATURE xss
        out.println("<div>" + values.get(2) + "</div>");
    }

    // The map form. Two keys written, a third read. Key matching is deliberately
    // not attempted - see keyed-container.java, a second guess stacked on a
    // first - so the honest output is a report without a proof.
    public void manyPutsIsAGuess(HttpServletRequest req, PrintWriter out) {
        java.util.HashMap<String, String> map = new java.util.HashMap<>();
        map.put("clean", "a_value");
        map.put("dirty", req.getParameter("q"));
        // EXPECT-SIGNATURE xss
        out.println("<div>" + map.get("clean") + "</div>");
    }

    // ---- THE GUARD: ACCUMULATORS ARE NOT COLLECTIONS ----
    //
    // Four appends, one of them dirty. Unlike a list, there is no element to
    // pick wrongly: toString() returns all four concatenated, so the dirty one
    // is unavoidably in the output. Counting writes here would be counting the
    // wrong thing, and this must stay PROVEN.
    public void appendStaysProvenHoweverManyTimes(HttpServletRequest req, PrintWriter out) {
        StringBuilder sb = new StringBuilder();
        sb.append("<p>");
        sb.append(req.getParameter("name"));
        sb.append("</p>");
        sb.append("<hr>");
        // EXPECT-FLOW xss
        out.println(sb.toString());
    }
}
