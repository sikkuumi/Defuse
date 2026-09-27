<?php
/*
 * A SWITCH ON A NUMBER, IN PHP.
 *
 * PHP compares cases with LOOSE equality, where "1e1" == "10" and, before PHP
 * 8, 0 == "a". So only a number compared with a number is decided here; any
 * other pairing keeps every case live. PHP also names its default case
 * `default_statement` rather than reusing `case_statement`, which is one more
 * grammar-shaped name the folder has to be told about rather than assume.
 */

// ---------------------------------------------------------------- DECIDED

function dead_case($conn): void {
    $param = $_GET['p'];
    $mode = 2;
    switch ($mode) {
        case 1:
            $bar = $param;
            break;
        case 2:
            $bar = "constant";
            break;
        default:
            $bar = $param;
    }
    // EXPECT-CLEAN sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function live_default($conn): void {
    $param = $_GET['p'];
    $mode = 7;
    switch ($mode) {
        case 1:
            $bar = "constant";
            break;
        default:
            $bar = $param;
    }
    // EXPECT-FLOW sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

// ---------------------------------------------------------------- THE FENCE

function falls_through($conn): void {
    $param = $_GET['p'];
    $mode = 2;
    switch ($mode) {
        case 2:
            $bar = "constant";
        case 3:
            $bar = $param;
            break;
        default:
            $bar = "other";
    }
    // EXPECT-FLOW sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}
