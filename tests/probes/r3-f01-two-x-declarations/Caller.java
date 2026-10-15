// r3-f01-two-x-declarations: A shape the constant proof read correctly when it was probed; kept so it stays that way.
package app;
public class Caller {
    static class Other { static class X { String m() { return "safe"; } } }
    void run(java.sql.Statement stmt) throws Exception {
        X h = new X();
        String bar = h.m();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
