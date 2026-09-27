/*
 * A MAP NOBODY ELSE CAN TOUCH GIVES BACK EXACTLY WHAT WAS PUT UNDER THE KEY.
 *
 *     HashMap<String, Object> map = new HashMap<String, Object>();
 *     map.put("keyA", "a_Value");
 *     map.put("keyB", param);
 *     bar = (String) map.get("keyB");      // the request parameter
 *     bar = (String) map.get("keyA");      // "a_Value" - and this is the one kept
 *
 * 57 of BenchmarkJava's safe cases are this shape. The engine taints a
 * collection WHOLE - it does not know which element a read takes out - so
 * `map.get("keyA")` came back dirty and every one of them was reported.
 *
 * keyed-container.java refuses to match keys, and it is right to: a request's
 * attributes can be written by filters and frameworks the scan never sees, so
 * matching the key there is a guess. A map that is created here, never handed
 * to anything, and only ever written by `put` with a literal key in plain
 * straight-line code is different - every write to it is on the page. For THAT
 * map, the value under a key is a fact, not a guess.
 *
 * So the read is resolved only when all of this holds, and every doubt keeps
 * the old whole-collection answer:
 *   - a local `new HashMap` or `new LinkedHashMap`, created with no arguments;
 *   - every mention of it is `map.put(literal, value);` as its own statement in
 *     the block that declared it, or `map.get(literal)` - it is never passed,
 *     returned, stored, iterated, or touched by any other method;
 *   - the read is not inside a lambda or an inner class, which could run later;
 *   - some `put` under that key comes before the read, and the last one wins.
 *
 * The same reasoning answers the SQL rule, which also needs one more fact: the
 * value of `bar` at the query is its LAST certain write. The fence below is the
 * list of shapes that look resolvable and must not be.
 */
import javax.servlet.http.*;

public class KeyedMapRead extends HttpServlet {

    // ---------------------------------------------------------------- RESOLVED

    // The BenchmarkJava shape: the tainted read is overwritten by the safe one.
    void safeKeyWins(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar = "safe!";
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", "a_Value");
        map.put("keyB", param);
        map.put("keyC", "another_Value");
        bar = (String) map.get("keyB");
        bar = (String) map.get("keyA");
        // EXPECT-CLEAN sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The vulnerable half: the read takes out exactly the dirty value. This was
    // a guess ("which element came out?") and is now a proof.
    void dirtyKeyRead(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", "a_Value");
        map.put("keyB", param);
        String bar = (String) map.get("keyB");
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // Two puts under one key: the later one is what comes out.
    void lastPutWins(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", "a_Value");
        map.put("keyA", param);
        String bar = (String) map.get("keyA");
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // ---------------------------------------------------------------- THE FENCE

    // A put that might not run: the map may still hold the dirty value.
    void conditionalPut(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", param);
        if (param.length() > 3) map.put("keyA", "a_Value");
        String bar = (String) map.get("keyA");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The map is handed to a helper, which can write anything under any key.
    void mapEscapes(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", "a_Value");
        map.put("keyB", param);
        fill(map, param);
        String bar = (String) map.get("keyA");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    private void fill(java.util.Map<String, Object> m, String v) {
        m.put("keyA", v);
    }

    // Any method other than put and get is a write this does not model. Here
    // putIfAbsent looks like a put under "keyA" - and it does nothing, because
    // "keyA" is already there. Reading it as the last put would call this clean.
    void otherMutator(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", param);
        map.putIfAbsent("keyA", "a_Value");
        String bar = (String) map.get("keyA");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // A key that is a variable could be any key.
    void variableKey(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String k = request.getParameter("k");
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", "a_Value");
        map.put(k, param);
        String bar = (String) map.get("keyA");
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The read sits in a lambda that runs AFTER the dirty put, though it is
    // written before it. Textual order is not execution order here.
    void readInLambda(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", "a_Value");
        java.util.function.Consumer<String> later = (s) -> {
            try {
                String bar = (String) map.get("keyA");
                // EXPECT sql-injection
                stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
            } catch (java.sql.SQLException e) {
                throw new RuntimeException(e);
            }
        };
        map.put("keyA", param);
        later.accept("run");
    }

    // The value put is an object that is changed AFTER the put. The map holds the
    // same object, so the read sees the change.
    void mutatedAfterPut(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        StringBuilder sb = new StringBuilder("a_Value");
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", sb);
        sb.append(param);
        String bar = map.get("keyA").toString();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The same, through an ALIAS the tracer does not follow: `alias.append()`
    // changes the object the map holds, and nothing writes to `sb` by name. A
    // mutable value is therefore never read at the get - only a String, a
    // primitive or a box is - and this falls back to "the whole map is dirty".
    // A page sink with no HTML around it, so no pattern rule can cover for it.
    void aliasMutatedAfterPut(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = request.getParameter("p");
        StringBuilder sb = new StringBuilder("a_Value");
        StringBuilder alias = sb;
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", sb);
        map.put("keyB", param);
        alias.append(param);
        String bar = map.get("keyA").toString();
        // EXPECT xss
        response.getWriter().println(bar);
    }

    // The last write before the query is certain - but a write AFTER the query,
    // inside the loop, reaches it on the next pass.
    void writeAfterUseInLoop(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar = "safe";
        for (int i = 0; i < 3; i++) {
            // EXPECT sql-injection
            stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
            bar = param;
        }
    }

    // The last write is inside an if, so the earlier dirty one may be the value.
    void conditionalLastWrite(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        String bar = param;
        if (param.length() > 3) bar = "safe";
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
