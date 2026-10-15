// r3-c07-try-skipped-write-stored: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class T {
    void run(java.sql.Statement stmt) throws Exception {
        String s = lookup("p");
        try { mayThrow(); s = "safe"; } catch (Exception e) { }
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("k", s);
        String bar = (String) map.get("k");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
