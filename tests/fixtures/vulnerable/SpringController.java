// FIXTURE: Spring request bindings as taint sources.
//
// WHY THIS FILE EXISTS, and it is the most uncomfortable entry in the suite.
//
// BenchmarkJava reports 76.4% recall for Java. Scanning OWASP WebGoat - an
// application built entirely OUT of deliberate, labelled vulnerabilities -
// produced 126 findings and ZERO flow-verified. Elasticsearch, 3,999 Java
// files: also zero.
//
// The cause is one line in the dictionary's own notes: "Spring @RequestParam-
// annotated parameters are not recognised as sources." WebGoat contains 161
// @RequestParam and 4 getParameter(). BenchmarkJava is the reverse - raw
// servlet getParameter/getHeader throughout.
//
// So the recall number was real and measured a dialect almost nobody writes
// any more. Every modern Spring application got zero data-flow coverage while
// the headline said 76%. That is the exact failure the honesty convention
// exists to prevent, and a benchmark score is what hid it.

package fixtures;

import org.springframework.web.bind.annotation.*;
import java.sql.Connection;
import java.sql.Statement;

@RestController
public class SpringController {

  private Connection connection;

  @PostMapping("/account")
  @ResponseBody
  public String lookup(@RequestParam String account, @RequestParam String operator) {
    return injectableQuery(account + " " + operator);
  }

  protected String injectableQuery(String accountName) throws Exception {
    String query = "SELECT * FROM user_data WHERE last_name = '" + accountName + "'";
    Statement statement = connection.createStatement();
    // EXPECT-FLOW sql-injection
    statement.executeQuery(query);
    return query;
  }

  @GetMapping("/ping")
  public String ping(@PathVariable String host) throws Exception {
    // EXPECT-FLOW command-injection
    Runtime.getRuntime().exec("ping -c 1 " + host);
    return "ok";
  }

  @GetMapping("/search")
  public String search(@RequestHeader("X-Filter") String filter) throws Exception {
    Statement statement = connection.createStatement();
    // EXPECT-FLOW sql-injection
    statement.executeQuery("SELECT * FROM docs WHERE title LIKE '%" + filter + "%'");
    return "ok";
  }

  // An ordinary parameter with no binding annotation is NOT a source. Whoever
  // calls this decides what is in it, and that caller may well be safe.
  public String helper(String plain) throws Exception {
    Statement statement = connection.createStatement();
    statement.executeQuery("SELECT * FROM t WHERE x = '" + plain + "'");
    return "ok";
  }
}
