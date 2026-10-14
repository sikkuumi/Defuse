// p17-block-local-shadow: The constant `table` is a local of an inner block; the read after the block is the field.
package app;
public class Caller {
    private final String table;

    Caller() {
        table = lookup("t");
    }

    void list(java.sql.Statement stmt, boolean audit) throws Exception {
        if (audit) {
            String table = Boolean.getBoolean("legacy") ? "audit_v1" : "audit";
            stmt.execute("INSERT INTO " + table + " VALUES (1)");
        }
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM " + table);
    }
}
