// FIXTURE: the SAFE versions, Java.
// EXPECT-NONE
import java.security.MessageDigest;
import java.sql.*;

public class SafeDao {
    public ResultSet findById(Connection conn, String id) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        return ps.executeQuery();
    }

    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");

    public MessageDigest strong() throws Exception {
        return MessageDigest.getInstance("SHA-256");
    }
}
