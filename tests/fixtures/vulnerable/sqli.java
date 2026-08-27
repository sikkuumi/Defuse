// FIXTURE: SQL injection, Java.
import java.sql.*;

public class UserDao {
    public ResultSet findById(Statement stmt, String id) throws SQLException {
        // EXPECT sql-injection
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    public int deleteByEmail(Statement stmt, String email) throws SQLException {
        // EXPECT sql-injection
        return stmt.executeUpdate("DELETE FROM users WHERE email = '" + email + "'");
    }
}
