// FIXTURE: server-side request forgery, Java.
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpRequest;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.client.RestTemplate;

public class Fetcher {
    private RestTemplate restTemplate = new RestTemplate();

    public InputStream open(HttpServletRequest request) throws Exception {
        // EXPECT-FLOW ssrf
        return new URL(request.getParameter("u")).openStream();
    }

    public URI uri(HttpServletRequest request) {
        // EXPECT-FLOW ssrf
        return URI.create(request.getParameter("u"));
    }

    public HttpRequest build(HttpServletRequest request) {
        String target = request.getParameter("u");
        // EXPECT-FLOW ssrf
        return HttpRequest.newBuilder(new java.net.URI(target)).build();
    }

    public String rest(HttpServletRequest request) {
        // EXPECT-FLOW ssrf
        return restTemplate.getForObject(request.getParameter("u"), String.class);
    }

    // A fixed start of the address pins the host: to review, not proven.
    public InputStream fixedHost(HttpServletRequest request) throws Exception {
        // EXPECT-SIGNATURE ssrf
        return new URL("https://api.example.com/items/" + request.getParameter("id")).openStream();
    }

    public InputStream constant() throws Exception {
        return new URL("https://api.example.com/status").openStream(); // SAFE
    }
}
