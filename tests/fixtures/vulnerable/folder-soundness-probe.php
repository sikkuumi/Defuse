<?php
// The PHP half of FolderSoundnessProbe.java - an adversarial probe's programs,
// each a real injection the constant folder hid before this was fixed.
function extract_overwrite($conn): void {
    $param = $_GET['p'];
    $n = 0;
    extract($_GET);
    $bar = $n > 5 ? $param : "safe";
    // EXPECT sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function short_list($conn): void {
    $param = $_GET['p'];
    $n = 0;
    [$n] = [strlen($param)];
    $bar = $n > 5 ? $param : "safe";
    // EXPECT sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function list_construct($conn): void {
    $param = $_GET['p'];
    $n = 0;
    list($n) = [strlen($param)];
    $bar = $n > 5 ? $param : "safe";
    // EXPECT sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function variable_variable($conn): void {
    $param = $_GET['p'];
    $n = 0;
    $field = 'n';
    $$field = strlen($param);
    $bar = $n > 5 ? $param : "safe";
    // EXPECT sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function brace_name($conn): void {
    $param = $_GET['p'];
    $n = 0;
    ${'n'} = strlen($param);
    $bar = $n > 5 ? $param : "safe";
    // EXPECT sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function eval_write($conn): void {
    $param = $_GET['p'];
    $n = 0;
    eval('$n = 7;');
    $bar = $n > 5 ? $param : "safe";
    // EXPECT sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function octal($conn): void {
    $param = $_GET['p'];
    $n = 010;
    $bar = $n < 9 ? $param : "safe";
    // EXPECT sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function division($conn): void {
    $param = $_GET['p'];
    $half = 7 / 2;
    $bar = $half > 3 ? $param : "safe";
    // EXPECT sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function closure_by_ref($conn): void {
    $param = $_GET['p'];
    $n = 0;
    $set = function ($v) use (&$n) { $n = $v; };
    $set(strlen($param));
    $bar = $n > 5 ? $param : "safe";
    // EXPECT sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function array_ref($conn): void {
    $param = $_GET['p'];
    $n = 0;
    $slots = [&$n];
    $slots[0] = strlen($param);
    $bar = $n > 5 ? $param : "safe";
    // EXPECT sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}

function division_switch($conn): void {
    $param = $_GET['p'];
    $mode = 7 / 2;
    switch ($mode) {
        case 3:
            $bar = "safe";
            break;
        default:
            $bar = $param;
    }
    // EXPECT sql-injection
    $conn->query("SELECT * FROM t WHERE x = '" . $bar . "'");
}
