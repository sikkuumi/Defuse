/*
 * THE NEAR MISSES. EVERY ONE OF THESE LOOKS LIKE A VALUE THE FOLDER SETTLED.
 *
 * The SQL rule may now withdraw a guess when every value spliced into the
 * string is provably a literal on every path that runs - see
 * constant-branch-dead.java for the cases it exists for. A withdrawal is a
 * claim that a line is clean, and a wrong one hides a real bug, so this file is
 * the fence: each case is the nearest shape to a withdrawable one that must
 * NOT be withdrawn, plus one that looks risky and genuinely is fixed.
 *
 * The values here come from parameters and from a method we cannot see into,
 * never from a recognised source, so the tracer has nothing to say and every
 * verdict below is the signature rule's alone.
 */
public abstract class ConstantProofFence {

    abstract String lookup();

    // A parameter is input, whatever the method does to it afterwards. The
    // literal write only happens when `flag` is set, and the caller's value
    // reaches the string every other time.
    void parameterReassignedUnderUnknownCondition(String bar, boolean flag,
                                                  java.sql.Statement stmt) throws Exception {
        if (flag) {
            bar = "constant";
        }
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // Two live writes, and only one of them is a literal.
    void oneLiveWriteIsNotALiteral(boolean flag, java.sql.Statement stmt) throws Exception {
        String bar = "constant";
        if (flag) {
            bar = lookup();
        }
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The folder DOES decide this condition - onto the side it cannot see into.
    // Deciding a branch is not the same as the branch being a constant.
    void decidedOntoAnUnknown(java.sql.Statement stmt) throws Exception {
        int num = 106;
        String bar = (7 * 18) + num > 200 ? lookup() : "constant";
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The dead arm is the literal and the live arm is the unknown: the mirror
    // image of the BenchmarkJava decoy. Dropping the dead write is right; what
    // is left is still not a constant.
    void deadArmIsTheLiteral(java.sql.Statement stmt) throws Exception {
        String bar;
        if (1 > 2) {
            bar = "constant";
        } else {
            bar = lookup();
        }
        // EXPECT-SIGNATURE sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // Undecidable - but both arms are literals, so every value that can reach
    // the string is fixed. This is the one near miss that IS clean, and it is
    // here so the fence cannot be passed by refusing every ternary.
    void bothArmsLiteral(boolean flag, java.sql.Statement stmt) throws Exception {
        String bar = flag ? "asc" : "desc";
        // EXPECT-CLEAN sql-injection
        stmt.execute("SELECT * FROM t ORDER BY x " + bar);
    }
}
