// p16-pattern-shadows-field: The pattern variable `table` shadows the constant field of the same name.
package app;
public class Caller {
    private static final String table = Boolean.getBoolean("legacy") ? "users_v1" : "users";

    void list(java.sql.Statement stmt) throws Exception {
        Object o = lookup("t");
        if (o instanceof String table) {
            // EXPECT sql-injection
            stmt.execute("SELECT * FROM " + table);
        }
    }
}
