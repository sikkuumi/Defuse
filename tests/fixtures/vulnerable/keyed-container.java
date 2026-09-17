// TAINT LEAKED OUT OF A COMPARTMENT IT WAS PUT INTO.
//
// Found by re-scanning Jenkins after the escaper fix. One flow-verified finding
// survived, and it survived for a reason worth writing down, because it walked
// straight around the fix that had just been built.
//
// hudson/util/HudsonAuthenticationEntryPoint.java:
//
//     req.setAttribute("loginForm", loginForm);           // taint stored INTO req
//     ...
//     Util.printRedirect(req.getContextPath(), loginForm, "...", out);
//                        ^^^^^^^^^^^^^^^^^^^^
//
// `setAttribute` is a mutator, so storing a tainted value into `req` marked the
// WHOLE `req` OBJECT tainted. `getContextPath()` is not in the dictionary, and
// an unmodelled call carries its receiver's taint - so the servlet context path,
// a constant configured by the container and utterly unrelated to the stored
// attribute, came back dirty.
//
// The second half is what makes it more than one false positive. The tracer
// then blamed printRedirect's FIRST parameter (contextPath) rather than its
// second (loginForm) - and the second is the one Jenkins escapes with
// Functions.htmlAttributeEscape. So the misattribution moved the finding onto
// the one argument that was NOT escaped, and the escaper retraction shipped one
// version earlier never got a chance to fire. A precision bug in one place
// disguised itself as a real finding in another.
//
// THE DISTINCTION BEING DRAWN. Not all mutators are alike:
//
//   sb.append(dirty)          the container IS the value. sb.toString() is
//                             dirty, and so is every other read of sb. Correct
//                             as it stands, and this file must not change it.
//
//   req.setAttribute(k,dirty) the object holds the value in a side compartment
//                             under a NAME. It is primarily something else -
//                             it has a method, a URI, a session, a context
//                             path. A keyed READ of the same store is dirty.
//                             Unrelated methods on it are not.
//
// The narrow rule: a keyed write dirties the keyed store, not the object.
//
// The imprecision is NOT removed, only aimed. getAttribute() with any key still
// comes back dirty - see the vulnerable counterpart. This file is only about
// the methods that never touched the compartment at all.
//
// WHY THIS IS NOT AN EXPECT-NONE FILE, which is the more interesting half.
//
// My first draft asserted these lines produce NOTHING, and that draft was
// wrong - it would have demanded a lie in the opposite direction. Look at what
// the signature rule sees:
//
//     out.println("<div>" + req.getContextPath() + "</div>")
//
// A method result concatenated into HTML. A pattern matcher cannot know that
// getContextPath() returns a container-configured constant, and staying quiet
// would be claiming knowledge it does not have. Flagging it UNVERIFIED is the
// honest output.
//
// What was actually wrong at Jenkins was not that the line was mentioned. It
// was the CONFIDENCE LABEL: the tracer said "attacker-controlled data reaches
// this sink, every hop listed, this is not a pattern guess". That is a
// different sentence and a false one.
//
// So these lines are annotated EXPECT-SIGNATURE - a new annotation, added for
// this fixture, because the test vocabulary could say "fired" and "fired with
// proof" and had no way at all to say "fired WITHOUT claiming proof". The one
// distinction the whole project is built on was the one the tests could not
// assert. Now they can.

import java.io.PrintWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class KeyedContainer {

    // The Jenkins shape, reduced. `uriFrom` is genuinely attacker-controlled and
    // is genuinely stored into the request - but none of the three values read
    // back below ever passed through that store.
    public void jenkinsShape(HttpServletRequest req, PrintWriter out) {
        String uriFrom = req.getRequestURI() + "?" + req.getQueryString();
        req.setAttribute("loginForm", uriFrom);

        // Container-configured constants. Reading them from an object that
        // happens to be carrying a dirty attribute does not make them dirty -
        // so these may be GUESSED at, and must never be claimed as proven.
        // EXPECT-SIGNATURE xss
        out.println("<div>" + req.getContextPath() + "</div>");
        // EXPECT-SIGNATURE xss
        out.println("<div>" + req.getServletPath() + "</div>");
        // EXPECT-SIGNATURE xss
        out.println("<div>" + req.getMethod() + "</div>");
    }

    // Response headers are the same shape in the other direction: setHeader
    // writes into a keyed store, and the status code is not in it.
    public void headerStore(HttpServletRequest req, HttpServletResponse resp, PrintWriter out) {
        resp.setHeader("X-Echo", req.getParameter("q"));
        // EXPECT-SIGNATURE xss
        out.println("<p>" + resp.getStatus() + "</p>");
    }

    // ---- THE HALF THAT KEEPS THE FIX FROM BECOMING A SILENCE ----
    //
    // Narrowing taint propagation is the most dangerous change available in
    // this engine, because its failure mode is silence, and a scanner that has
    // gone quiet is indistinguishable from a scanner that has been fixed. Every
    // shape the narrowing must NOT touch is written down below.

    // The keyed store READ BACK. This is the flow the compartment rule exists
    // to preserve: same object, same store, and the value really did come from
    // the attacker. Deliberately key-insensitive - we do not check that the key
    // matches, because matching key literals would be a second guess stacked on
    // a first - so this fires whichever name is used.
    public void readsTheStoreBack(HttpServletRequest req, PrintWriter out) {
        req.setAttribute("q", req.getParameter("q"));
        // EXPECT xss
        out.println("<div>" + req.getAttribute("q") + "</div>");
    }

    // Accumulating mutators are untouched. `sb` IS the tainted string, so
    // toString() - an unmodelled call reading a dirty receiver, the exact shape
    // the rule intercepts - has to keep carrying the taint.
    public void accumulatorIsTheValue(HttpServletRequest req, PrintWriter out) {
        StringBuilder sb = new StringBuilder();
        sb.append(req.getParameter("name"));
        // EXPECT xss
        out.println("<div>" + sb.toString() + "</div>");
    }

    // A collection, same reasoning: the list is the payload, so reading any
    // element of it is reading the payload.
    public void collectionIsTheValue(HttpServletRequest req, PrintWriter out) {
        java.util.List<String> parts = new java.util.ArrayList<>();
        parts.add(req.getParameter("part"));
        // EXPECT xss
        out.println("<div>" + parts.get(0) + "</div>");
    }
}
