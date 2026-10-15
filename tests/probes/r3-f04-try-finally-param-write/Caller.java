// r3-f04-try-finally-param-write: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class Caller {
    static class X {
        String m(String v) { try { return v; } finally { v = lookup("p"); } }
    }
    void run(java.sql.Statement stmt) throws Exception {
        X h = new X();
        String bar = h.m(lookup("q"));
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
