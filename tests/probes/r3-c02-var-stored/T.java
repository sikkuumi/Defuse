// r3-c02-var-stored: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class T {
    void run(java.sql.Statement stmt) throws Exception {
        var s = lookup("p");
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("k", s);
        String bar = (String) map.get("k");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
