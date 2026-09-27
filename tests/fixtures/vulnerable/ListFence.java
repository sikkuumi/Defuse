/*
 * List operations the replay in taint/local-map.ts does not model, each of
 * which moves or replaces what sits at a position: addAll, clear, sort, an
 * iterator's remove, adds inside a try that may throw first, and a read inside
 * a lambda that runs after later writes. Probed before the list proof shipped;
 * every one is a real injection that must stay reported.
 */
import javax.servlet.http.*;
public class ListFence extends HttpServlet {
    void addAll(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> list = new java.util.ArrayList<String>();
        list.add("safe");
        list.addAll(0, java.util.Arrays.asList(param));
        String bar = list.get(0);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
    void clearThenAdd(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> list = new java.util.ArrayList<String>();
        list.add("safe");
        list.clear();
        list.add(param);
        String bar = list.get(0);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
    void sortList(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> list = new java.util.ArrayList<String>();
        list.add("zzz");
        list.add(param);
        list.sort(null);
        String bar = list.get(1);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
    void iterRemove(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> list = new java.util.ArrayList<String>();
        list.add("safe");
        list.add(param);
        java.util.Iterator<String> it = list.iterator();
        it.next(); it.remove();
        String bar = list.get(0);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
    void addInTry(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> list = new java.util.ArrayList<String>();
        list.add(param);
        try { risky(); list.add(0 < 1 ? "x" : "y"); list.remove(0); } catch (Exception e) {}
        String bar = list.get(0);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
    void getInLambda(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> list = new java.util.ArrayList<String>();
        list.add("safe");
        Runnable r = () -> {
            try {
                // EXPECT sql-injection
                stmt.execute("SELECT * FROM t WHERE x = '" + list.get(0) + "'");
            } catch (Exception e) {
            }
        };
        list.remove(0);
        list.add(param);
        r.run();
    }
    void risky() throws Exception {}
}
