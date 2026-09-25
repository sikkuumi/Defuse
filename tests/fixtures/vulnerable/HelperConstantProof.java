/*
 * ONE LEVEL INTO A HELPER, AND NOT ONE STEP FURTHER.
 *
 * After the constant folder was shared with the signature rules, 46 of
 * BenchmarkJava's SQL false positives still survived, and every one of them had
 * the same structure: the decoy was not in the method that builds the SQL, it
 * was in a helper that method calls.
 *
 *     String bar = new Test().doSomething(request, param);
 *     String sql = "SELECT ... '" + bar + "'";
 *     ...
 *     private class Test {
 *         public String doSomething(HttpServletRequest request, String param) {
 *             bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
 *             return bar;
 *
 * The tracer already follows that call, which is why the green label carries
 * no decoys. The signature rule stopped at the method boundary.
 *
 * WHAT THE PROOF WILL FOLLOW, AND ONLY THIS:
 *
 *   - a call whose receiver is `new X(...)` - so the type is exact and no
 *     subclass anywhere can be the one that actually runs;
 *   - or a bare call to a method of the SAME class that is private or static -
 *     neither can be overridden, so the declaration here is the one that runs.
 *     (27 of the survivors were this shape; BenchmarkJava declares its helpers
 *     `private static`.) A bare call to anything else could be a subclass's;
 *   - X declared in THIS file, declaring exactly ONE method of that name - an
 *     overload is a question about arguments this proof does not ask;
 *   - every `return` in that method yielding a value already provable by the
 *     same rules as everywhere else - a literal, a decided branch, a ternary
 *     whose arms are all literals;
 *   - one level. A helper that returns another helper's result is not followed.
 *
 * Everything below the positive case is a near miss that must stay reported.
 * The values come from plain parameters and from methods with no body, never
 * from a recognised source, so every verdict here is the signature rule's.
 */
public abstract class HelperConstantProof {

    abstract String lookup();

    // The shape the proof exists for.
    void decoyInsideTheHelper(String param, java.sql.Statement stmt) throws Exception {
        String bar = new Test().doSomething(param);
        // EXPECT-CLEAN sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The same decoy behind a bare call to a private static helper.
    void privateStaticHelper(String param, java.sql.Statement stmt) throws Exception {
        String bar = decoy(param);
        // EXPECT-CLEAN sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // ---------------------------------------------------------------- FENCES

    // A bare call to a method a subclass is free to override: the declaration
    // below may not be the one that runs.
    void overridableHelper(String param, java.sql.Statement stmt) throws Exception {
        String bar = overridable(param);
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // One return is fixed, the other is the caller's value.
    void oneReturnIsInput(String param, java.sql.Statement stmt) throws Exception {
        String bar = new TwoReturns().pick(param);
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The helper decides its branch - onto the parameter.
    void helperPicksTheInput(String param, java.sql.Statement stmt) throws Exception {
        String bar = new LiveArm().doSomething(param);
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // Two methods of the same name: which one runs depends on the argument
    // types, and that is a question this proof does not ask.
    void overloadedHelper(String param, java.sql.Statement stmt) throws Exception {
        String bar = new Overloaded().get(param);
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The receiver is a variable, so the object could be any subclass at all.
    void receiverIsNotAConstructor(Test helper, String param, java.sql.Statement stmt) throws Exception {
        String bar = helper.doSomething(param);
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // Two levels deep. The inner helper IS constant; the proof still stops.
    void twoLevelsDeep(String param, java.sql.Statement stmt) throws Exception {
        String bar = new Wrapper().outer(param);
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // A class this file does not declare: nothing here says what it returns.
    void helperFromElsewhere(String param, java.sql.Statement stmt) throws Exception {
        String bar = new java.lang.StringBuilder(param).toString();
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // ---------------------------------------------------------------- HELPERS

    private static String decoy(String param) {
        String bar;
        int num = 86;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;
        return bar;
    }

    // Same body, but public and non-static: overridable, so not followed.
    public String overridable(String param) {
        String bar;
        int num = 86;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;
        return bar;
    }

    private class Test {
        public String doSomething(String param) {
            String bar;
            int num = 106;
            bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
            return bar;
        }
    }

    private class TwoReturns {
        public String pick(String param) {
            if (param.isEmpty()) {
                return "default";
            }
            return param;
        }
    }

    private class LiveArm {
        public String doSomething(String param) {
            String bar;
            int num = 196;
            if ((500 / 42) + num > 200) bar = param;
            else bar = "This should never happen";
            return bar;
        }
    }

    private class Overloaded {
        public String get(String param) {
            return "fixed";
        }

        public String get(Object other) {
            return String.valueOf(other);
        }
    }

    private class Wrapper {
        public String outer(String param) {
            return new Test().doSomething(param);
        }
    }
}
