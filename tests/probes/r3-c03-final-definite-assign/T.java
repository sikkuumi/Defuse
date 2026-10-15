// r3-c03-final-definite-assign: A shape the constant proof read correctly when it was probed; kept so it stays that way.
public class T {
    void run(java.sql.Statement stmt, boolean c) throws Exception {
        final String s;
        if (c) s = "safe"; else s = lookup("p");
        java.util.List<String> list = new java.util.ArrayList<String>();
        list.add("a");
        list.add(s);
        String bar = list.get(1);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
