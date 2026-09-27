/*
 * A LIST NOBODY ELSE CAN TOUCH GIVES BACK WHAT SITS AT THE POSITION.
 *
 *     List<String> valuesList = new ArrayList<String>();
 *     valuesList.add("safe");
 *     valuesList.add(param);
 *     valuesList.add("moresafe");
 *     valuesList.remove(0);             // everything shifts down one
 *     bar = valuesList.get(1);          // "moresafe"
 *
 * 323 BenchmarkJava cases are this list, and it was the largest single cause
 * of false positives left: the collection is tainted whole, so `get(1)` came
 * back dirty. The list is now REPLAYED - every add and remove that certainly
 * runs before the read, in order - under the same conditions as the map in
 * KeyedMapRead.java: created here, handed to nothing, written only by
 * straight-line `add(value);` and `remove(literal);` statements in its own
 * block. taint/local-map.ts has the full list, and the fence below is every
 * shape that looks replayable and is not.
 */
import javax.servlet.http.*;

public class ListIndexRead extends HttpServlet {

    // ---------------------------------------------------------------- RESOLVED

    // The BenchmarkJava shape: after remove(0), index 1 is "moresafe".
    void safeIndex(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar = "alsosafe";
        if (param != null) {
            java.util.List<String> valuesList = new java.util.ArrayList<String>();
            valuesList.add("safe");
            valuesList.add(param);
            valuesList.add("moresafe");
            valuesList.remove(0);
            bar = valuesList.get(1);
        }
        // EXPECT-CLEAN sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The vulnerable half: after remove(0), index 0 is the parameter.
    void dirtyIndex(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar = "";
        if (param != null) {
            java.util.List<String> valuesList = new java.util.ArrayList<String>();
            valuesList.add("safe");
            valuesList.add(param);
            valuesList.add("moresafe");
            valuesList.remove(0);
            bar = valuesList.get(0);
        }
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // ---------------------------------------------------------------- THE FENCE

    // Without the remove, index 1 IS the parameter. A replay that ignored the
    // remove above would get the safe case wrong; one that applied a remove
    // that is not there would get this one wrong.
    void noRemove(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(param);
        valuesList.add("moresafe");
        String bar = valuesList.get(1);
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // remove("safe") removes by VALUE, not position - not modelled. Here it
    // takes out index 0 and leaves the parameter at 0; skipping it would leave
    // "safe" there and call this clean.
    void removeByValue(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(param);
        valuesList.remove("safe");
        String bar = valuesList.get(0);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // add(index, value) inserts - not modelled.
    void insertAt(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(0, param);
        String bar = valuesList.get(0);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // An add that might not run shifts every later position, or does not: when
    // it does not run, index 0 is the parameter.
    void conditionalAdd(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        if (param.length() > 3) valuesList.add("pad");
        valuesList.add(param);
        valuesList.add("safe");
        String bar = valuesList.get(0);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The list is handed to something that can reorder it.
    void listEscapes(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add(param);
        valuesList.add("safe");
        java.util.Collections.reverse(valuesList);
        String bar = valuesList.get(1);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // set() overwrites a position - not modelled.
    void setOverwrites(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.set(0, param);
        String bar = valuesList.get(0);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The index is not a literal.
    void variableIndex(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(param);
        int i = param.length() % 2;
        String bar = valuesList.get(i);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // A list built with its contents (a copy constructor) holds values unseen.
    void copied(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.List<String> source = java.util.Arrays.asList(param, "safe");
        java.util.List<String> valuesList = new java.util.ArrayList<String>(source);
        valuesList.add("moresafe");
        String bar = valuesList.get(0);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
