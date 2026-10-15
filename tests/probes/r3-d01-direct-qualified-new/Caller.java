// r3-d01-direct-qualified-new: a06 called directly: `o.new X().m()`.
package app;
class X { String m() { return "safe"; } }
public class Caller {
    void run(Lib o, java.sql.Statement stmt) throws Exception {
        String bar = o.new X().m();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
