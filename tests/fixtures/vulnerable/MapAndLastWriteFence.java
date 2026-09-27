/*
 * CONTROL FLOW THAT MAKES A "LAST WRITE" OR A MAP PUT UNCERTAIN.
 *
 * Every method here is a real SQL injection that the two new proofs - the
 * local-map read (taint/local-map.ts) and the last certain write (the SQL
 * rule's constant proof) - must NOT explain away: a write inside a try that
 * may throw first, a read in the catch, a labeled break that skips the write,
 * a put in a try, getOrDefault, a put nested inside another put's argument, and
 * a second map of the same name in a sibling block. Written as probes before
 * shipping, and kept so they stay caught.
 */
import javax.servlet.http.*;
public class MapAndLastWriteFence extends HttpServlet {
    void tryCatch(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String bar = request.getParameter("p");
        try { bar = "safe"; risky(); } catch (Exception e) { }
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
    void catchRead(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String bar = request.getParameter("p");
        try {
            risky();
            bar = "safe";
        } catch (Exception e) {
            // EXPECT sql-injection
            stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
        }
    }
    void labeled(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String bar = request.getParameter("p");
        out: { if (bar.isEmpty()) break out; bar = "safe"; }
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
    void mapInTry(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", param);
        try { risky(); map.put("keyA", "safe"); } catch (Exception e) { }
        String bar = (String) map.get("keyA");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
    void mapGetOrDefault(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", "safe");
        String bar = (String) map.getOrDefault("keyB", param);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
    void nestedPut(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", "safe");
        map.put("keyB", String.valueOf(map.put("keyA", param)));
        String bar = (String) map.get("keyA");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
    void siblingShadow(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        { java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>(); map.put("keyA", param); }
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", "safe");
        map.put("keyB", param);
        String bar = (String) map.get("keyA");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
    void risky() throws Exception {}
}
