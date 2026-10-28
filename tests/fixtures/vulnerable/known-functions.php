<?php
// FIXTURE: what common PHP functions RETURN, so a proof does not rest on a guess.
//
// A function this engine does not know is assumed to hand back its argument,
// and the path says so ("NOT in our dictionary - we assume it preserves the
// value"). On DVWA that guess was right for stripslashes() and basename() and
// wrong for the database reads: mysqli_query() and mysqli_fetch_assoc() return
// stored rows, not the query text, and an AI review of the published proofs
// marked every path through them wrong. md5() and isset() were the same
// mistake in the other direction - their output cannot carry the input's text.

// ---- They hand back the attacker's text, changed but not cleaned ----------

function greet() {
  $name = stripslashes($_GET['name']);
  // EXPECT-FLOW xss
  echo "<p>Hello $name</p>";
}

function uploaded() {
  $file = basename($_FILES['upload']['name']);
  // EXPECT-FLOW xss
  echo "<pre>{$file} was uploaded</pre>";
}

// DVWA's xss_r/source/high.php: removing one spelling of <script> leaves every other tag.
function filtered() {
  $name = preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET['name']);
  // EXPECT-FLOW xss
  echo "<pre>Hello $name</pre>";
}

// ---- The value of `cond ? a : b` is a or b, never the condition ------------

// The proof used to run through isset() in the condition. It is still real,
// through the branch that hands the cookie back.
function role() {
  $role = isset($_COOKIE['role']) ? $_COOKIE['role'] : 'guest';
  // EXPECT-FLOW xss
  echo "<div>Role: {$role}</div>";
}

// ---- A database read returns stored rows, not the query --------------------

// Escaped inside quotes, the query cannot be injected, so what comes back is a
// row stored in the database. The echo is a fair guess (stored data) and NOT a
// proof. DVWA's brute/source/medium.php - an AI review called the old proof wrong.
function avatarEscaped($conn) {
  $user = mysqli_real_escape_string($conn, $_GET['user']);
  // EXPECT-CLEAN sql-injection
  $result = mysqli_query($conn, "SELECT avatar FROM users WHERE user = '$user'");
  $row = mysqli_fetch_assoc($result);
  // EXPECT-SIGNATURE xss
  echo "<img src='" . $row['avatar'] . "'>";
}

// Unescaped, the query IS injectable, and `' UNION SELECT '<script>...` picks
// the row it returns. DVWA's brute/source/low.php - the same review called
// that proof real, for this reason and not the one the old path gave.
function avatarInjectable($conn) {
  $user = $_GET['user'];
  // EXPECT-FLOW sql-injection
  $result = mysqli_query($conn, "SELECT avatar FROM users WHERE user = '$user'");
  $row = mysqli_fetch_assoc($result);
  // EXPECT-FLOW xss
  echo "<img src='" . $row['avatar'] . "'>";
}

// ---- Output that cannot carry the input's text -----------------------------

// 32 hex characters, whatever went in.
function fingerprint() {
  // EXPECT weak-hash
  $hash = md5($_GET['file']);
  // EXPECT-CLEAN xss
  echo "<p>Fingerprint: $hash</p>";
}

// true or false, whatever went in.
function debugFlag() {
  $present = isset($_GET['debug']);
  // EXPECT-CLEAN xss
  echo "<p>Debug: " . $present . "</p>";
}

// ---- Fence: an option this engine does not read keeps the guess -----------

// md5(..., true) returns 16 RAW bytes, and raw bytes can contain a quote - the
// known 'ffifdyop' login bypass. Only the one-argument form is known to be hex.
function rawDigest($conn) {
  // EXPECT weak-hash
  $raw = md5($_POST['password'], true);
  // EXPECT-FLOW sql-injection
  return mysqli_query($conn, "SELECT * FROM users WHERE pass = '$raw'");
}
