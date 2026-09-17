// FIXTURE: JAX-RS request bindings as taint sources.
//
// The Jakarta/Java EE standard, and therefore the binding style used by Jersey,
// RESTEasy, Dropwizard and Quarkus. It is the same mechanism Spring uses - an
// annotation on the parameter declaration, with the framework doing the binding
// before the method body runs - so it costs six lines of dictionary and covers
// four more frameworks.
//
// Added the same hour the capability text started claiming JAX-RS was covered.
// A claim in the report and an entry in the dictionary have to ship together,
// or the report is lying about the engine it describes.

package fixtures;

import jakarta.ws.rs.*;
import java.sql.Connection;
import java.sql.Statement;

@Path("/accounts")
public class JaxrsResource {

  private Connection connection;

  @GET
  @Path("/lookup")
  public String lookup(@QueryParam("name") String name) throws Exception {
    Statement statement = connection.createStatement();
    // EXPECT-FLOW sql-injection
    statement.executeQuery("SELECT * FROM users WHERE last_name = '" + name + "'");
    return "ok";
  }

  @GET
  @Path("/{id}/ping")
  public String ping(@PathParam("id") String id) throws Exception {
    // EXPECT-FLOW command-injection
    Runtime.getRuntime().exec("ping -c 1 " + id);
    return "ok";
  }

  @POST
  @Path("/search")
  public String search(@HeaderParam("X-Filter") String filter,
                       @FormParam("q") String q,
                       @CookieParam("sid") String sid) throws Exception {
    Statement statement = connection.createStatement();
    // EXPECT-FLOW sql-injection
    statement.executeQuery("SELECT * FROM docs WHERE title LIKE '%" + filter + "%'");
    return q + sid;
  }

  // No binding annotation, so not a source: whoever calls this decides what is
  // in it, and that caller may well be safe.
  public String helper(String plain) throws Exception {
    Statement statement = connection.createStatement();
    statement.executeQuery("SELECT * FROM t WHERE x = '" + plain + "'");
    return "ok";
  }
}
