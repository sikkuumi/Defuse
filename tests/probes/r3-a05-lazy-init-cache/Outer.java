// r3-a05-lazy-init-cache: A lazily cached field holds what the FIRST call passed, not this call's literal.
import javax.servlet.http.*;

public class Outer {
    static class Memo {
        private String cached;
        // remembers the FIRST key it is given
        String get(String key) {
            if (cached == null) cached = key;
            return cached;
        }
    }

    void doGet(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        Memo h = new Memo();
        h.get(lookup("p"));
        String bar = h.get("x");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
