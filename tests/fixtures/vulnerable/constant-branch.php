<?php
/*
 * PHP FOLDS ITS TERNARY WRONG AND ITS `IF` HALF-WRONG. TWO DIFFERENT HOLES.
 *
 * See constant-branch.py for why the folder was checked outside Java at all.
 * PHP's grammar disagrees with Java in two places rather than one, and the
 * second is nastier than the first because it only breaks in one direction.
 *
 *   1. conditional_expression names `condition` and `alternative` but NOT
 *      `consequence` - the middle operand is an unnamed child. Reading it as a
 *      field gave null, so a decidably-true condition selected nothing and the
 *      value vanished. Vanishing is the wrong kind of wrong: it drops flows.
 *
 *   2. if_statement calls its body `body`, not `consequence`. So asking for the
 *      dead arm worked when the condition was TRUE (the else is `alternative`,
 *      which PHP does name) and returned null when it was FALSE. Half the
 *      decoys were dropped and half were kept, from one missing field name.
 *
 * The elvis form `$a ?: $b` is here too. It has two operands, not three: when
 * the condition is truthy the value IS the condition. The leftover-child search
 * that recovers PHP's middle operand finds nothing in that shape, so the
 * consequence falls back to the condition itself rather than to null - and null
 * there would have meant a silently dropped value.
 */

// ---------------------------------------------------------------- DEAD BRANCHES

function ternary_always_true($conn): void {
    $param = $_GET['p'];
    $num = 106;
    $bar = (7 * 18) + $num > 200 ? "constant" : $param;
    // EXPECT-SIGNATURE sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function ternary_always_false($conn): void {
    $param = $_GET['p'];
    $bar = 1 > 2 ? $param : "constant";
    // EXPECT-SIGNATURE sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

/*
 * THE SAME DECISION, ISOLATED FROM THE VARIABLE HOLE.
 *
 * ternary_always_false above passed before any fix, and that is not the good
 * news it looks like: a FALSE condition selects `alternative`, which is the one
 * part of a PHP ternary that IS named, so it never touched the missing field.
 * ternary_always_true needed `consequence` AND needed `$num` to fold, so its
 * failure could have been either hole or both.
 *
 * This case has no variable in the condition at all. `1 < 2` is two literals,
 * so the only thing it can be asking about is whether the middle operand can be
 * found. Without that, two holes shared one test between them and a half-fix
 * would have looked complete.
 */
function ternary_always_true_no_variable($conn): void {
    $param = $_GET['p'];
    $bar = 1 < 2 ? "constant" : $param;
    // EXPECT-SIGNATURE sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

// The `body` field hole: the condition is TRUE, so the tainted else is dead.
// This half worked before the fix, because PHP does name `alternative`.
function if_else_dead_else($conn): void {
    $param = $_GET['p'];
    $num = 106;
    if ((7 * 18) + $num > 200) {
        $bar = "constant";
    } else {
        $bar = $param;
    }
    // EXPECT-SIGNATURE sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

// The other half, and the one that was broken: the condition is FALSE, so the
// tainted THEN-body is dead - and the then-body is the field PHP does not name.
function if_else_dead_then($conn): void {
    $param = $_GET['p'];
    if (1 > 2) {
        $bar = $param;
    } else {
        $bar = "constant";
    }
    // EXPECT-SIGNATURE sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

// No else at all, so the dead arm is the whole statement body.
function never_taken($conn): void {
    $bar = "constant";
    if (false) {
        $bar = $_GET['p'];
    }
    // EXPECT-SIGNATURE sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

// ------------------------------------------------------------------ LIVE BRANCHES

function ternary_picks_the_taint($conn): void {
    $param = $_GET['p'];
    $num = 106;
    $bar = (7 * 18) + $num > 200 ? $param : "constant";
    // EXPECT-FLOW sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function if_live_arm($conn): void {
    $param = $_GET['p'];
    if (1 < 2) {
        $bar = $param;
    } else {
        $bar = "constant";
    }
    // EXPECT-FLOW sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function undecidable_condition($conn): void {
    $bar = "constant";
    if ($_GET['mode'] === "raw") {
        $bar = $_GET['p'];
    }
    // EXPECT-FLOW sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

// The elvis form with an undecidable left side. Nothing folds, both operands
// are live, and the tainted one must still come through.
function elvis_keeps_the_taint($conn): void {
    $bar = $_GET['fallback'] ?: "constant";
    // EXPECT-FLOW sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}
