// r3-c08-lambda-block-map: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class T {
    void run(java.sql.Statement stmt, java.util.List<String> xs) throws Exception {
        xs.forEach((String s) -> {
            java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
            map.put("k", s);
            String bar = (String) map.get("k");
            // EXPECT sql-injection
            try { stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'"); } catch (Exception e) { }
        });
        String s = "safe";
    }
}
