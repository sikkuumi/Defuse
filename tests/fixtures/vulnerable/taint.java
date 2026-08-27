// FIXTURE: verified data flows, Java (Servlet API + JDBC).
import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class TaintFixture {
    public ResultSet throughAVariable(HttpServletRequest request, Statement stmt) throws SQLException {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = " + id;
        // EXPECT-FLOW sql-injection
        return stmt.executeQuery(sql);
    }

    public void intoAShell(HttpServletRequest request) throws Exception {
        // EXPECT-FLOW command-injection
        Runtime.getRuntime().exec("ping -c 1 " + request.getParameter("host"));
    }

    private String buildQuery(String value) {
        return "SELECT * FROM users WHERE name = '" + value + "'";
    }

    public ResultSet acrossFunctions(HttpServletRequest request, Statement stmt) throws SQLException {
        // EXPECT-FLOW sql-injection
        return stmt.executeQuery(buildQuery(request.getParameter("q")));
    }
}
