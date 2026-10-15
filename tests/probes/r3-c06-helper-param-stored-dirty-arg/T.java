// r3-c06-helper-param-stored-dirty-arg: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class T {
    static class H {
        String pick(String p) {
            java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
            map.put("k", p);
            return (String) map.get("k");
        }
    }
    void run(java.sql.Statement stmt) throws Exception {
        H h = new H();
        String bar = h.pick(lookup("p"));
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
