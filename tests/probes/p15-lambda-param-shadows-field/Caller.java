// p15-lambda-param-shadows-field: The lambda parameter `table` shadows the constant field of the same name.
package app;
public class Caller {
    private static final String table = Boolean.getBoolean("legacy") ? "users_v1" : "users";

    void purge(java.sql.Statement stmt) {
        java.util.List<String> names = lookup("tables");
        names.forEach(table -> {
            // EXPECT sql-injection
            try { stmt.execute("DELETE FROM " + table); } catch (Exception e) { }
        });
    }
}
