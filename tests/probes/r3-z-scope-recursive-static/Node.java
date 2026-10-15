// r3-z-scope-recursive-static: a07 through a private static method.
public class Node {
    private static String m(String a, String b, java.sql.Statement stmt) throws Exception {
        if (stmt == null) return a;
        String bar = m(b, "x", null);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
        return a;
    }
}
