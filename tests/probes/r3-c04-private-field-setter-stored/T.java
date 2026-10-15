// r3-c04-private-field-setter-stored: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class T {
    private String s = "safe";
    void set(String v) { s = v; }
    void run(java.sql.Statement stmt) throws Exception {
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("k", s);
        String bar = (String) map.get("k");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
    void other() { if (true) { String s = "x"; } }
}
