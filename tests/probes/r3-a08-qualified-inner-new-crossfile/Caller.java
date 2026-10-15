// r3-a08-qualified-inner-new-crossfile: a06 with the top-level X in another file.
package app;
public class Caller {
    void run(Lib o, java.sql.Statement stmt) throws Exception {
        Lib.X h = o.new X();
        String bar = h.m();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
