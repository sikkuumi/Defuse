<?php
// FIXTURE: a cleared line says what cleared it - and what it took on trust.
//
// The report's "Checked and cleared" section used to print one sentence for
// every line the data-flow engine cleared: "A sanitiser for this kind of
// problem was proven to run on the path into this line." It said that for an
// allow-list check, for a hex digest, and for DVWA's ping output, which was
// cleared because the ping's ADDRESS was checked and shell_exec() - a function
// Defuse does not model - was taken to hand back what it was given.
//
// Now each cleared line carries a receipt: the step that cleaned the value
// for that kind of sink, the line it was on, and every function Defuse does
// not model that the value went through AFTER the cleaning.

// A function nobody models runs BEFORE the escaping. It cannot undo what has
// not happened yet, so the receipt rests on nothing but htmlspecialchars().
function before_the_escape() {
    $raw = format_name($_GET['name']);
    // EXPECT-CLEAN xss
    echo '<p>' . htmlspecialchars($raw) . '</p>';
}

// The same function runs AFTER the escaping. If it decoded entities, the
// line would be an XSS - so the receipt must say it was assumed not to.
function after_the_escape() {
    $safe = htmlspecialchars($_GET['name']);
    // EXPECT-CLEAN xss
    echo '<p>' . format_name($safe) . '</p>';
}

// Escaping that only holds inside quotes, used inside quotes. The receipt
// says where the value sits, because that is half of why it is safe.
function quoted($db) {
    $name = mysqli_real_escape_string($db, $_GET['name']);
    // EXPECT-CLEAN sql-injection
    return mysqli_query($db, "SELECT * FROM users WHERE name = '$name'");
}

// Two cleaned values joined. The first went through the unmodelled function
// BEFORE it was escaped, so nothing here rests on trust - the receipt must
// not list format_name(). (OWASP BenchmarkJava has 24 of these: a file read
// through classes Defuse does not model, then escaped, beside an escaped name.)
function cleaned_before_joining() {
    $a = htmlspecialchars(format_name($_GET['a']));
    $b = htmlspecialchars($_GET['b']);
    // EXPECT-CLEAN xss
    echo '<p>' . $b . ' and ' . $a . '</p>';
}

// Two cleaned values joined, and the SECOND went through it after escaping.
// The receipt must list it, whichever side of the join it came from.
function trusted_on_the_right() {
    $a = htmlspecialchars($_GET['a']);
    $b = format_name(htmlspecialchars($_GET['b']));
    // EXPECT-CLEAN xss
    echo '<p>' . $a . ' and ' . $b . '</p>';
}
