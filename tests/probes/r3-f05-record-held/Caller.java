// r3-f05-record-held: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class Caller {
    record X(String v) { String m() { return v; } }
    void run(java.sql.Statement stmt) throws Exception {
        X h = new X(lookup("p"));
        String bar = h.m();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
