import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;

// FIXTURE: path traversal (CWE-22) in Java. The File is the sink: the tracer
// follows variables, not what an object holds, so the read on a later line
// is not where the finding lands.
public class PathTraversal {
  public byte[] read(HttpServletRequest request) throws Exception {
    String name = request.getParameter("name");
    // EXPECT-FLOW path-traversal
    File file = new File("/var/reports/" + name);
    return Files.readAllBytes(file.toPath());
  }

  public FileInputStream stream(HttpServletRequest request) throws Exception {
    // EXPECT-FLOW path-traversal
    return new FileInputStream(new File("/uploads", request.getParameter("f")));
  }

  public byte[] nio(HttpServletRequest request) throws Exception {
    // EXPECT-FLOW path-traversal
    return Files.readAllBytes(Paths.get("/data", request.getParameter("p")));
  }
}
