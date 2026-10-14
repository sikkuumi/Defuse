// p18-read-before-local-decl: The first read comes before the local is declared, so it reads the field.
package app;
public class Caller {
    private final String table;

    Caller() {
        table = lookup("t");
    }

    void list(java.sql.Statement stmt) throws Exception {
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM " + table);
        String table = Boolean.getBoolean("legacy") ? "audit_v1" : "audit";
        stmt.execute("INSERT INTO " + table + " VALUES (1)");
    }
}
