import javax.servlet.http.*;

/**
 * decodeBase64(encodeBase64(x)) is x. encodeBase64 is not modelled and its name
 * says "encode", which alone would make the trace a mere possibility - but the
 * decode that undoes it IS modelled, so it never appears as an unmodelled hop.
 * Checking only those hops cost BenchmarkJava 69 correct proofs.
 */
public class Base64RoundTrip extends HttpServlet {

    public void roundTrip(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("q");
        String bar = new String(
                org.apache.commons.codec.binary.Base64.decodeBase64(
                        org.apache.commons.codec.binary.Base64.encodeBase64(param.getBytes())));
        // EXPECT-FLOW xss
        response.getWriter().println(bar);
    }
}
