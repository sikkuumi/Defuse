# THE CONSTANT FOLDER WAS WRITTEN AGAINST JAVA AND VERIFIED AGAINST JAVA.
#
# constant-branch-dead.java and constant-branch-live.java prove it works. They
# prove it works IN JAVA, and nothing in the suite said whether the other seven
# languages folded at all - so the honest assumption was that they did not, and
# the honest thing to do was go and look.
#
# They did not. Two separate grammar differences, each silent:
#
#   1. `A if C else B` names nothing. Java's ternary has condition/consequence/
#      alternative fields; Python's conditional_expression has no fields at all
#      and its children are in WRITTEN order, so the value comes first and the
#      condition is in the middle. Reading `condition` as a field gave null,
#      folding null gave "cannot tell", and every Python ternary stayed live.
#
#   2. `a > b` names nothing either. comparison_operator has no left, no right
#      and no operator field - Python allows `1 < x < 5`, so a comparison is a
#      LIST of operands rather than a pair. That one is worse than the ternary,
#      because it means no Python comparison folded anywhere: not in a ternary,
#      not in an `if`, not in the `underCondition` check.
#
# Neither failed loudly. Both resolved to "cannot tell", which is the folder's
# safe direction, so Python simply kept every false positive Java had stopped
# having and no test anywhere said a word about it. A blind spot that fails
# safe is still a blind spot, and this file is what makes it say something.
#
# The dead cases assert EXPECT-CLEAN: no finding, and a proved-clean record.
# They asserted EXPECT-SIGNATURE until the folder was shared with the signature
# rules - see constant-branch-dead.java for why that assertion was right then
# and is wrong now. The live cases are unchanged, and matter more.
#
# The live cases are the fence. The cheapest way to pass "drop taint on dead
# branches" is to drop taint at every branch, which would score beautifully and
# silence the real findings this tool exists for. Every case below the fold has
# attacker data on a branch that really runs, or behind a condition the engine
# cannot decide, and every one must survive.
import sys


# ---------------------------------------------------------------- DEAD BRANCHES

# The shape BenchmarkJava uses. 126 + 106 = 232, always > 200, so the tainted
# value is on the side that never runs.
def ternary_always_true(cursor):
    param = sys.argv[1]
    num = 106
    bar = "constant" if (7 * 18) + num > 200 else param
    # EXPECT-CLEAN sql-injection
    cursor.execute("SELECT * FROM t WHERE x = '" + bar + "'")


# The same decision spelled the other way round.
def ternary_always_false(cursor):
    param = sys.argv[1]
    bar = param if 1 > 2 else "constant"
    # EXPECT-CLEAN sql-injection
    cursor.execute("SELECT * FROM t WHERE x = '" + bar + "'")


# An if/else where the taint is in the dead arm.
def if_else_dead_arm(cursor):
    param = sys.argv[1]
    num = 106
    if (7 * 18) + num > 200:
        bar = "constant"
    else:
        bar = param
    # EXPECT-CLEAN sql-injection
    cursor.execute("SELECT * FROM t WHERE x = '" + bar + "'")


# A literal guard - the debug path that never runs. Python spells its booleans
# True and False, which foldLiteral already accepted; this is the one case that
# worked before the fix and it is here so a regression cannot hide.
def never_taken(cursor):
    bar = "constant"
    if False:
        bar = sys.argv[1]
    # EXPECT-CLEAN sql-injection
    cursor.execute("SELECT * FROM t WHERE x = '" + bar + "'")


# ------------------------------------------------------------------ LIVE BRANCHES

# The constant decision lands on the TAINTED side.
def ternary_picks_the_taint(cursor):
    param = sys.argv[1]
    num = 106
    bar = param if (7 * 18) + num > 200 else "constant"
    # EXPECT-FLOW sql-injection
    cursor.execute("SELECT * FROM t WHERE x = '" + bar + "'")


# An if/else whose LIVE arm carries the value.
def if_else_live_arm(cursor):
    param = sys.argv[1]
    if 1 < 2:
        bar = param
    else:
        bar = "constant"
    # EXPECT-FLOW sql-injection
    cursor.execute("SELECT * FROM t WHERE x = '" + bar + "'")


# A condition the engine cannot decide. This is the common case in real code and
# it must behave exactly as it did before: the value is carried, because
# refusing to guess means assuming the branch may run.
def undecidable_condition(cursor, mode):
    param = sys.argv[1]
    bar = "constant"
    if mode == "raw":
        bar = param
    # EXPECT-FLOW sql-injection
    cursor.execute("SELECT * FROM t WHERE x = '" + bar + "'")


# `NOT` IS THE ONE THAT COULD HAVE DELETED A FINDING, AND IT IS WHY THIS FILE
# EXISTS AT ALL RATHER THAN A ONE-LINE PATCH TO THE TERNARY.
#
# not_operator has no `operator` field either - the `not` token is an unnamed
# child, exactly like the `>` in a comparison. The folder's unary branch needs
# an operator field, so it skipped; the next branch down unwraps a node with a
# single named child; and not_operator has a single named child. So `not True`
# folded to TRUE.
#
# Every other hole in this file fails SAFE. A condition that will not fold means
# "cannot tell", the branch is assumed live, the value is carried, and the worst
# outcome is a false positive that was already there. This one fails the other
# way: it asserts that a branch runs when it does not, and then the engine skips
# the arm that REALLY runs and stops reporting a real vulnerability.
#
# `not True` is false, so the alternative is what executes, so the taint arrives
# at the sink. If this line is ever reported as anything less than flow-verified
# - or not reported at all - the folder is answering conditions backwards.
def not_operator_picks_the_alternative(cursor):
    param = sys.argv[1]
    bar = "constant" if not True else param
    # EXPECT-FLOW sql-injection
    cursor.execute("SELECT * FROM t WHERE x = '" + bar + "'")


# The same operator resolving the other way, so a fix cannot pass by ignoring
# `not` altogether. `not False` is true, the constant side runs, the taint is in
# dead code.
def not_operator_dead_arm(cursor):
    param = sys.argv[1]
    bar = "constant" if not False else param
    # EXPECT-CLEAN sql-injection
    cursor.execute("SELECT * FROM t WHERE x = '" + bar + "'")


# A CHAINED comparison, which is the Python-only shape and the reason
# comparison_operator has no left/right in the first place. `1 < 2 < 3` is true,
# and the folder is not going to work that out - it handles exactly two operands
# and returns "cannot tell" for anything longer. Cannot tell means the branch is
# assumed live, so the taint survives, which is the safe direction and the one
# this case pins down.
def chained_comparison_not_folded(cursor):
    param = sys.argv[1]
    bar = "constant" if 1 < 2 < 3 else param
    # EXPECT-FLOW sql-injection
    cursor.execute("SELECT * FROM t WHERE x = '" + bar + "'")
