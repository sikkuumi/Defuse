// r3-a07-recursive-self-binding: A method calling itself: the caller's own parameters are not the callee's.
public class Node {
    // m is both the helper being read AND the method holding the sink
    String m(String a, String b, java.sql.Statement stmt) throws Exception {
        if (stmt == null) return a;
        Node h = new Node();
        String bar = h.m(b, "x", null);      // returns ITS a, i.e. OUR b
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
        return a;
    }
}
