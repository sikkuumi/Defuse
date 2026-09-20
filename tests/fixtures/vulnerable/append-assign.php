<?php
/*
 * `.=` EXTENDS A VALUE, AND PHP IS HERE BECAUSE IT WAS THE ONE THAT SURVIVED.
 *
 * See append-assign.js for the full story. When the bug was measured across
 * languages, JavaScript, TypeScript, Python, Java, Go and the C family all
 * lost the value and PHP alone kept it - its `.=` happened to take a different
 * path through the tracer.
 *
 * Passing by luck is not the same as passing by design, and the fix touched
 * the shared code that PHP was accidentally avoiding. So this file is not a
 * regression test for a bug PHP had; it is a regression test for the one it
 * did not have, and must keep not having now that it runs through the same
 * line as everyone else.
 */

function trailing_constant(): void {
    $sql = "SELECT * FROM users WHERE name = '";
    $sql .= $_GET['name'];
    $sql .= "'";
    // EXPECT-FLOW sql-injection
    mysqli_query($conn, $sql);
}

function leading_constant(): void {
    $cmd = "ping ";
    $cmd .= "-c 1 ";
    $cmd .= $_GET['host'];
    // EXPECT-FLOW command-injection
    system($cmd);
}

/*
 * The over-fix guard, and PHP needs a different annotation from the other five.
 *
 * Elsewhere this case asserts silence: a real overwrite clears the value, so
 * nothing is reported. In PHP something IS reported, and measuring showed it
 * has nothing to do with the fix - `$cmd = "ping -c 1 localhost"; system($cmd);`
 * with no taint anywhere in the function fires exactly the same way. PHP's
 * signature pass flags a command built from a variable regardless of where the
 * variable came from, and a bare literal inside system() does not fire at all.
 *
 * So the assertion here is the sharper one: the finding may appear, but it must
 * NOT carry a proof. A flow-verified label on this line would mean the
 * overwrite had stopped clearing the value, which is the over-fix this whole
 * case exists to catch - and EXPECT-SIGNATURE says that in one word.
 */
function real_reassignment_still_clears(): void {
    $cmd = "ping ";
    $cmd .= $_GET['host'];
    $cmd = "ping -c 1 localhost";
    // EXPECT-SIGNATURE command-injection
    system($cmd);
}
