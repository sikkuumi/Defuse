// r3-b03-static-field-written-outside: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class Outer {
    static class Box {
        private static String F = "safe";
        String get() { return F; }
    }
    void run(java.sql.Statement stmt) throws Exception {
        Box h = new Box();
        Box.F = lookup("p");
        String bar = h.get();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
