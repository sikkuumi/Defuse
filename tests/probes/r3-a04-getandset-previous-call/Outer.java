// r3-a04-getandset-previous-call: The held object keeps a field from an EARLIER call: swap() returns what the previous call stored.
import javax.servlet.http.*;

public class Outer {
    static class Slot {
        private String f = "safe";
        // getAndSet: hands back what the PREVIOUS call stored
        String swap(String v) {
            String old = f;
            f = v;
            return old;
        }
    }

    void doGet(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        Slot h = new Slot();
        h.swap(lookup("p"));
        String bar = h.swap("x");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
