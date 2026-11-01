<?php
// FIXTURE: a washed value beside an unwashed one in the same string.
//
// Interpolation used to take the FIRST dirty part as the whole string, so a
// number in front made the query look washed and the header after it was
// "checked and cleared". DVWA's bac/low.php logs exactly this: an intval'd id
// and a raw X-Forwarded-For header in one INSERT.
function log_access($db) {
    $a = intval($_GET['a']);
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    $q = "INSERT INTO log VALUES ({$a}, '{$ip}')";
    // EXPECT-FLOW sql-injection
    return mysqli_query($db, $q);
}

// The same with `.`, which always kept only what both sides washed - but told
// the story through the LEFT side, so the finding named the washed number.
function log_access_joined($db) {
    $a = intval($_GET['a']);
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    $q = "INSERT INTO log VALUES (" . $a . ", '" . $ip . "')";
    // EXPECT-FLOW sql-injection
    return mysqli_query($db, $q);
}
