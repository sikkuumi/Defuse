// p19-nested-class-field-not-in-scope: The constant TABLE belongs to a nested class; the read is the statically imported one.
package app;
import static app.Settings.TABLE;
public class Caller {
    static class Defaults {
        private static final String TABLE = Boolean.getBoolean("legacy") ? "users_v1" : "users";
    }

    void list(java.sql.Statement stmt) throws Exception {
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM " + TABLE);
    }
}
