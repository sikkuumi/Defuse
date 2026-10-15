// r3-z-scope-static-swap: a04 through a static field and `new Slot().swap(...)`.
public class Outer {
    static class Slot {
        private static String f = "safe";
        String swap(String v) { String old = f; f = v; return old; }
    }
    void run(java.sql.Statement stmt) throws Exception {
        new Slot().swap(lookup("p"));
        String bar = new Slot().swap("x");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
