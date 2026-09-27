<?php
/*
 * The PHP half of FolderSoundness.java.
 *
 *   by_reference   preg_match() fills its third argument BY REFERENCE, and
 *                  nothing at the call site says so - PHP decides that in the
 *                  callee's signature. So in PHP, handing a variable to any
 *                  call means it may have been rewritten.
 *   param_once     a parameter holds the caller's value before any `=`
 */

function by_reference($conn): void {
    $param = $_GET['p'];
    $n = 0;
    preg_match('/(\d+)/', $param, $n);
    $bar = $n > 5 ? $param : "safe";
    // EXPECT-FLOW sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function param_once($conn, $num): void {
    $param = $_GET['p'];
    if ($param === '') $num = 500;
    $bar = $num > 200 ? "safe" : $param;
    // EXPECT-FLOW sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}
