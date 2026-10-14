// p14-comment-says-final: The word final appears only in a comment; the field is public and written from another class.
package app;
public class Caller {
    public /* final once config lands */ static String table =
        Boolean.getBoolean("legacy") ? "users_v1" : "users";

    void list(java.sql.Statement stmt) throws Exception {
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM " + table);
    }
}
