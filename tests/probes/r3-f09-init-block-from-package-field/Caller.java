// r3-f09-init-block-from-package-field: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class Caller {
    static String CFG = "safe";
    static class X {
        private String f;
        { f = CFG; }
        String m() { return f; }
    }
    void run(java.sql.Statement stmt) throws Exception {
        X h = new X();
        String bar = h.m();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
