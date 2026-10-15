// r3-f03-local-out-of-scope-field-h: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class Caller {
    static class X { String m() { return "safe"; } }
    static class Y { String m() { return lookup("p"); } }
    private Y h = new Y();
    void run(java.sql.Statement stmt) throws Exception {
        { X h = new X(); h.m(); }
        String bar = h.m();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
