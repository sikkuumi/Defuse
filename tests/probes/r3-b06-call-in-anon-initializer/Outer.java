// r3-b06-call-in-anon-initializer: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class Outer {
    static class Box {
        String get() { return "safe"; }
    }
    static class Base { Base h = null; String get() { return lookup("p"); } }
    void run(java.sql.Statement stmt) throws Exception {
        Box h = new Box();
        new Base() {{
            String bar = h.get();
            // EXPECT sql-injection
            try { stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'"); } catch (Exception e) {}
        }};
    }
}
