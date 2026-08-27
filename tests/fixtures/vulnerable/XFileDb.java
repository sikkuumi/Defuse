// FIXTURE (cross-file): the sink lives here. Same package as XFileHandler,
// so Java sees it with no import statement at all.
import java.sql.*;

public class XFileDb {
    public static ResultSet runQueryXF(Statement stmt, String sqlText) throws SQLException {
        // EXPECT-FLOW sql-injection
        return stmt.executeQuery(sqlText);
    }
}
