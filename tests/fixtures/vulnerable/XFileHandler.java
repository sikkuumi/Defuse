// FIXTURE (cross-file): the source lives here.
import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class XFileHandler {
    public ResultSet handle(HttpServletRequest request, Statement stmt) throws SQLException {
        return XFileDb.runQueryXF(stmt, "SELECT * FROM users WHERE id = " + request.getParameter("id"));
    }
}
