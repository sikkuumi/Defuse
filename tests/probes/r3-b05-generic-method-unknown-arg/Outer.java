// r3-b05-generic-method-unknown-arg: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class Outer {
    static class Box {
        synchronized <T> String get(T k) { return "v" + k; }
    }
    void run(java.sql.Statement stmt) throws Exception {
        Box h = new Box();
        Object o = lookup("p");
        String bar = h.get(o);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
