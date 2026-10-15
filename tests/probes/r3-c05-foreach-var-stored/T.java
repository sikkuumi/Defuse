// r3-c05-foreach-var-stored: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class T {
    void run(java.sql.Statement stmt, java.util.List<String> xs) throws Exception {
        { String s = "safe"; }
        for (String s : xs) {
            java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
            map.put("k", s);
            String bar = (String) map.get("k");
            // EXPECT sql-injection
            stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
        }
    }
}
