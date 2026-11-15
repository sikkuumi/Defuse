import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;

// FIXTURE: the fix for path traversal in Java, which must stay quiet.
public class PathTraversalSafe {
  public byte[] read(HttpServletRequest request) throws Exception {
    String name = Paths.get(request.getParameter("name")).getFileName().toString();
    // EXPECT-CLEAN path-traversal
    return Files.readAllBytes(new File("/var/reports", name).toPath());
  }

  public byte[] fixed() throws Exception {
    return Files.readAllBytes(new File("/etc/app/config.json").toPath());
  }
}
