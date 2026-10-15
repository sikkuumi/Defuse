// r3-b02-this-field-return: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class Outer {
    static class Box {
        private String f = "safe";
        Box(String v) { this.f = v; }
        String get() { String r = f; return r; }
    }
    void run(java.sql.Statement stmt) throws Exception {
        Box h = new Box(lookup("p"));
        String bar = h.get();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
