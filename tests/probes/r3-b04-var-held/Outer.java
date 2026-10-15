// r3-b04-var-held: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class Outer {
    static class Box {
        String get(String k) { return k; }
    }
    void run(java.sql.Statement stmt) throws Exception {
        var h = new Box();
        String bar = h.get(lookup("p"));
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
