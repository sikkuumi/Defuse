/*
 * A MAP OR LIST READ THAT GIVES BACK A NAME, NOT A LITERAL.
 *
 * The constant proof answered `map.get("keyB")` only when the value stored
 * there was a literal. BenchmarkJava's helpers store a NAME:
 *
 *     map.put("keyB", param);            // param is "bar", from getTheValue()
 *     bar = (String) map.get("keyB");
 *
 * The read now gives back that name's value AS IT WAS WHEN STORED - the put is
 * where it is judged, not the get - when its declared type cannot change in
 * place (a String, a boxed number). The tracer has read stored names this way
 * since KeyedMapRead.java; this is the proof doing the same.
 *
 * `lookup` is defined nowhere in the scan, so the tracer has no source to
 * follow and the pattern rule is the only thing that speaks.
 */
import javax.servlet.http.*;

public class ContainerHeldValue extends HttpServlet {

    // ---------------------------------------------------------------- RESOLVED

    void mapOfName(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String fixedValue = "safe";
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", lookup("p"));
        map.put("keyB", fixedValue);
        String bar = (String) map.get("keyB");
        // EXPECT-CLEAN sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    void listOfName(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String fixedValue = "safe";
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add(lookup("p"));
        valuesList.add(fixedValue);
        String bar = valuesList.get(1);
        // EXPECT-CLEAN sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // ---------------------------------------------------------------- THE FENCE

    // Unknown when stored, a literal afterwards: the map still holds the
    // unknown one. Judging the name at the get would call this clean.
    void cleanedAfterStoring(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String v = lookup("p");
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyB", v);
        v = "safe";
        String bar = (String) map.get("keyB");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The same for a list.
    void listCleanedAfterStoring(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String v = lookup("p");
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add(v);
        v = "safe";
        String bar = valuesList.get(0);
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
