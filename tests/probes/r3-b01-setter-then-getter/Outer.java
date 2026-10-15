// r3-b01-setter-then-getter: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class Outer {
    static class Box {
        private String f = "safe";
        void set(String v) { f = v; }
        String get() { return f; }
    }
    void run(java.sql.Statement stmt) throws Exception {
        Box h = new Box();
        h.set(lookup("p"));
        String bar = h.get();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
