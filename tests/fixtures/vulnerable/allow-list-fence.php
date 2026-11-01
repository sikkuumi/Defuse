<?php
// FIXTURE: the fence around safe/allow-list-guards.php.
//
// A check that counts silences a line, and silence is the one failure this
// scanner cannot see in itself. Every check below LOOKS like an allow-list and
// lets something dangerous through, or sits where its fact no longer holds.
// Each line must still be reported.

// ---- 1. PATTERNS THAT DO NOT PIN THE WHOLE VALUE ----

function not_anchored() {
    $h = $_GET['host'];
    if (preg_match('/\d+/', $h)) {          // "1; rm -rf /" contains a digit
        // EXPECT-FLOW command-injection
        return shell_exec('ping ' . $h);
    }
}

function start_only() {
    $h = $_GET['host'];
    if (preg_match('/^\d+/', $h)) {         // starts with digits, then anything
        // EXPECT-FLOW command-injection
        return shell_exec('ping ' . $h);
    }
}

function multi_line() {
    $h = $_GET['host'];
    if (preg_match('/^\d+$/m', $h)) {       // "1\n; id" has a line of digits
        // EXPECT-FLOW command-injection
        return shell_exec('ping ' . $h);
    }
}

function split_anchors() {
    $h = $_GET['host'];
    if (preg_match('/^\d+|x$/', $h)) {      // "starts with digits" OR "ends with x"
        // EXPECT-FLOW command-injection
        return shell_exec('ping ' . $h);
    }
}

function whitespace_class() {
    $h = $_GET['host'];
    if (preg_match('/^[\w\s]+$/', $h)) {    // \s includes a newline: "a\nid"
        // EXPECT-FLOW command-injection
        return shell_exec('ping ' . $h);
    }
}

function negated_class() {
    $u = $_GET['u'];
    if (preg_match('/^[^<>]+$/', $u)) {     // no angle brackets, but quotes pass
        // EXPECT-FLOW xss
        echo "<a href='" . $u . "'>link</a>";
    }
}

// ---- 2. COMPARISONS THAT COUNT AN ERROR AS A PASS ----

function error_counts_as_match($db) {
    $x = $_GET['x'];
    // preg_match returns FALSE on bad UTF-8 under /u, and false !== 0.
    if (preg_match('/^\d+$/u', $x) !== 0) {
        // EXPECT-FLOW sql-injection
        return mysqli_query($db, "SELECT * FROM t WHERE id = '$x'");
    }
}

function false_means_no_match() {
    $x = $_GET['x'];
    // A plain no-match is 0, not false: this lets every non-number through.
    if (preg_match('/^\d+$/', $x) === false) {
        exit;
    }
    // EXPECT-FLOW command-injection
    return shell_exec('ls ' . $x);
}

// ---- 3. THE RIGHT CHECK, THE WRONG VALUE ----

// A check on one value, a query interpolating another. The first version of
// guards read the query text and found no pieces in it at all - string nodes
// were skipped whole - so the check on 'a' vouched for 'b'.
function different_value_interpolated($db) {
    if (is_numeric($_GET['a'])) {
        $b = $_GET['b'];
        $q = "SELECT * FROM t WHERE id = '$b'";
        // EXPECT-FLOW sql-injection
        return mysqli_query($db, $q);
    }
}

// Built from TWO request values; the check covers one of them.
function joined_with_unchecked() {
    $ext = $_GET['ext'];
    $file = $ext . '/' . $_GET['dir'];
    if ($ext === 'png') {
        // EXPECT-FLOW xss
        echo '<img src="' . $file . '">';
    }
}

// Built from the extension, then the extension variable is given a NEW value
// and that one is checked. The name still holds the first.
function checked_a_later_value() {
    $ext = $_GET['ext'];
    $file = 'upload.' . $ext;
    $ext = $_GET['other'];
    if ($ext === 'png') {
        // EXPECT-FLOW xss
        echo '<a href="' . $file . '">file</a>';
    }
}

// `.=` keeps what the name held before, and that was never checked.
function appended_then_checked() {
    $name = $_GET['name'];
    $ext = $_GET['ext'];
    $name .= $ext;
    if ($ext === 'png') {
        // EXPECT-FLOW xss
        echo '<p>' . $name . '</p>';
    }
}

// ---- 4. THE FACT STOPS HOLDING ----

function rewritten_inside() {
    $x = $_GET['x'];
    if (ctype_digit($x)) {
        $x = $_GET['y'];
        // EXPECT-FLOW command-injection
        return shell_exec('ls ' . $x);
    }
}

// The second time round the loop, $x is whatever the request said next.
function rewritten_later_in_a_loop($rows) {
    $x = $_GET['x'];
    if (ctype_digit($x)) {
        foreach ($rows as $r) {
            // EXPECT-FLOW command-injection
            shell_exec('ls ' . $x);
            $x = $_GET['next'];
        }
    }
}

// The exit is conditional, so the program can carry on unchecked.
function exit_only_sometimes($strict) {
    $x = $_GET['x'];
    if (!ctype_digit($x)) {
        if ($strict) {
            exit;
        }
    }
    // EXPECT-FLOW command-injection
    return shell_exec('ls ' . $x);
}

// ---- 5. ENOUGH FOR ONE SINK, NOT FOR ANOTHER ----

// PHP 7's `"abc" == 0` is true: a loose list of numbers lets anything in.
function loose_numbers() {
    $x = $_GET['x'];
    if (in_array($x, [0, 1])) {
        // EXPECT-FLOW command-injection
        return shell_exec('ls ' . $x);
    }
}

// Letters and digits are safe in a page and a shell, but a bare word in SQL
// is a column name: `WHERE c = c` is true for every row.
function word_outside_quotes($db) {
    $c = $_GET['c'];
    if (ctype_alnum($c)) {
        // EXPECT-FLOW sql-injection
        return mysqli_query($db, "SELECT * FROM t WHERE c = $c");
    }
}

// Digits are not a safe host: "2130706433" is 127.0.0.1 to most URL parsers.
function digits_are_a_host() {
    $h = $_GET['h'];
    if (ctype_digit($h)) {
        // EXPECT-FLOW ssrf
        return file_get_contents('http://' . $h . '/status');
    }
}

// ---- 6. WHICH SIDE OF THE CHECK ----

// A positive check: the else is where the value is NOT digits.
function used_in_the_else() {
    $x = $_GET['x'];
    if (ctype_digit($x)) {
        echo 'number';
    } else {
        // EXPECT-FLOW command-injection
        return shell_exec('ls ' . $x);
    }
}

// The program leaves only when BOTH hold. Without `strict`, $x is anything.
function and_in_the_else() {
    $x = $_GET['x'];
    if (!ctype_digit($x) && isset($_GET['strict'])) {
        exit;
    }
    // EXPECT-FLOW command-injection
    return shell_exec('ls ' . $x);
}

// The value only survives in the arm where the check FAILED.
function ternary_other_arm() {
    $x = $_GET['x'];
    $v = ctype_digit($x) ? 'number' : $x;
    // EXPECT-FLOW command-injection
    return shell_exec('ls ' . $v);
}

// Rebuilt from checked parts - and then overwritten on the way round the
// loop. Parameters, so only the signature rule sees it.
function rebuilt_then_overwritten($octet, $raw) {
    if (is_numeric($octet[0]) && is_numeric($octet[1])) {
        $target = $octet[0] . '.' . $octet[1];
        foreach ([1, 2] as $i) {
            // EXPECT command-injection
            shell_exec('ping ' . $target);
            $target = $raw;
        }
    }
}
