<?php
// FIXTURE: allow-list checks, read where the program stands after them.
//
// DVWA's scoreboard had seven wrong proofs, every one an allow-list the engine
// did not read: preg_match('/^\d+$/') in bac/medium.php (five), is_numeric on
// each octet in exec/impossible.php (the check was read, but the ping output
// it fed was not), and an extension list in upload/impossible.php. Each shape
// is reduced below. Every sink here must be CLEARED - reported as checked and
// clean, not merely left quiet. The fence is vulnerable/allow-list-fence.php.

// THE DVWA SHAPE: the error in the then-branch, the work in the else.
if (!preg_match('/^\d+$/', $_GET['user_id'])) {
    $html .= '<p>Invalid user ID format.</p>';
} else {
    $id = $_GET['user_id'];
    // EXPECT-CLEAN sql-injection
    mysqli_query($db, "SELECT user_id FROM users WHERE user_id = '$id'");
    // EXPECT-CLEAN xss
    $html .= "<p>No user found with ID: {$id}</p>";
}

// Leave early, then use it. Digits are safe unquoted too.
function page_by_exit($db) {
    if (!ctype_digit($_GET['page'])) {
        exit;
    }
    // EXPECT-CLEAN sql-injection
    return mysqli_query($db, 'SELECT * FROM posts LIMIT 10 OFFSET ' . $_GET['page']);
}

// die() with a message, a word pattern, a strict `!== 1`, and a shell.
function run_by_die() {
    $name = $_GET['name'];
    if (preg_match('/^[a-z0-9_]+$/iD', $name) !== 1) {
        die('bad name');
    }
    // EXPECT-CLEAN command-injection
    return shell_exec('id ' . $name);
}

// The canonical ORDER BY fix: a column name from a fixed list.
function sorted($db) {
    $sort = $_GET['sort'];
    if (in_array($sort, ['name', 'price', 'date'], true)) {
        // EXPECT-CLEAN sql-injection
        return mysqli_query($db, "SELECT * FROM products ORDER BY $sort");
    }
    return null;
}

// A list of words in a regex is a fixed list too - so it is safe unquoted.
function direction($db) {
    $dir = $_GET['dir'];
    if (preg_match('/^(?:asc|desc)$/i', $dir)) {
        // EXPECT-CLEAN sql-injection
        return mysqli_query($db, "SELECT * FROM products ORDER BY price $dir");
    }
    return null;
}

// THE UPLOAD SHAPE: the name is built from the extension BEFORE the check.
function upload() {
    $uploaded_name = $_FILES['uploaded']['name'];
    $ext = substr($uploaded_name, strrpos($uploaded_name, '.') + 1);
    $file = bin2hex(random_bytes(16)) . '.' . $ext;
    if (strtolower($ext) == 'jpg' || strtolower($ext) == 'jpeg' || strtolower($ext) == 'png') {
        // EXPECT-CLEAN xss
        echo "<a href='/uploads/{$file}'>{$file}</a> uploaded";
    }
}

// A ternary that only keeps the value when it is numeric.
function limited($db) {
    $per = is_numeric($_GET['per']) ? $_GET['per'] : 20;
    // EXPECT-CLEAN sql-injection
    return mysqli_query($db, 'SELECT * FROM t LIMIT ' . $per);
}

// \A and \z, a counted repeat, and a positive `=== 1`.
function zip_code() {
    if (preg_match('/\A[0-9]{5}\z/', $_POST['zip']) === 1) {
        // EXPECT-CLEAN xss
        echo '<p>Shipping to ' . $_POST['zip'] . '</p>';
    }
}

// POSIX classes, which PHP's regex engine understands.
function sequence() {
    $n = $_GET['n'];
    if (preg_match('/^[[:digit:]]{1,4}$/', $n)) {
        // EXPECT-CLEAN command-injection
        return shell_exec('seq ' . $n);
    }
    return '';
}

// Each part checked, then joined - and the program's OUTPUT printed. The
// output of a ping to a checked address is what DVWA's exec/impossible.php
// prints; it is only as attacker-controlled as the address it was given.
function ping_and_print() {
    $octet = explode('.', $_REQUEST['ip']);
    if (is_numeric($octet[0]) && is_numeric($octet[1]) && is_numeric($octet[2]) && is_numeric($octet[3])) {
        $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];
        $cmd = shell_exec('ping -c 4 ' . $target);
        // EXPECT-CLEAN xss
        echo "<pre>{$cmd}</pre>";
    }
}

// Else-if chains: the else knows every earlier condition was false, and an
// else-if body knows its own condition was true.
function else_after_elseif() {
    $x = $_GET['x'];
    if (isset($_GET['skip'])) {
        return '';
    } elseif (!ctype_digit($x)) {
        return 'bad';
    } else {
        // EXPECT-CLEAN command-injection
        return shell_exec('ls ' . $x);
    }
}

function inside_elseif() {
    $x = $_GET['x'];
    if (isset($_GET['skip'])) {
        return '';
    } elseif (ctype_digit($x)) {
        // EXPECT-CLEAN command-injection
        return shell_exec('ls ' . $x);
    }
    return '';
}
