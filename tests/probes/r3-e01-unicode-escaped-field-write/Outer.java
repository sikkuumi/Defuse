// r3-e01-unicode-escaped-field-write: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class Outer {
    static class Box {
        private String f = "safe";
        String get() { return f; }
    }
    void run(java.sql.Statement stmt) throws Exception {
        Box h = new Box();
        Box alias = h;
        alias.f = lookup("p");
        String bar = h.get();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
