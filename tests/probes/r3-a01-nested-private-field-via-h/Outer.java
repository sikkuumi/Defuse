// r3-a01-nested-private-field-via-h: A shape the constant proof read correctly when it was probed; kept so it stays that way.
import javax.servlet.http.*;

public class Outer {
    static class X {
        private String f = "safe";
        String m() { return f; }
    }

    void doGet(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        X h = new X();
        h.f = lookup("p");
        String bar = h.m();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
