// r3-a06-qualified-inner-new: `o.new X()` creates o's member class X, not the top-level X the name finds.
package app;

import javax.servlet.http.*;

class X {                                  // top-level app.X
    String m() { return "safe"; }
}

public class Caller {
    void doGet(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        Lib o = new Lib();
        var h = o.new X();                 // creates a Lib.X, not an app.X
        String bar = h.m();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
