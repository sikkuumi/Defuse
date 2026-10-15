// r3-c01-loop-carried-after-put: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class T {
    void run(java.sql.Statement stmt) throws Exception {
        String s = "safe";
        for (int i = 0; i < 3; i++) {
            java.util.HashMap<String, String> map = new java.util.HashMap<String, String>();
            map.put("k", s);
            String bar = map.get("k");
            // EXPECT sql-injection
            stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
            s = lookup("p");
        }
    }
}
