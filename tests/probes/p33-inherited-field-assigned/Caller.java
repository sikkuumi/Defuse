// p33-inherited-field-assigned: `table` is a field inherited from Base, declared nowhere in this file; refresh() reassigns it between the write in view and the read.
package app;
public class Caller extends Base {
    void list(java.sql.Statement stmt) throws Exception {
        table = "users";
        refresh();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM " + table);
    }
}
