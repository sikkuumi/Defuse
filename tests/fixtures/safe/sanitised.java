// FIXTURE: properly sanitised flows, Java.
// EXPECT-NONE
import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class SafeTaintFixture {
    // A number cannot carry a quote.
    public ResultSet numeric(HttpServletRequest request, Statement stmt) throws SQLException {
        int id = Integer.parseInt(request.getParameter("id"));
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    // Parameterised: the value is never part of the instruction.
    public ResultSet parameterised(HttpServletRequest request, Connection conn) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, request.getParameter("id"));
        return ps.executeQuery();
    }
}
