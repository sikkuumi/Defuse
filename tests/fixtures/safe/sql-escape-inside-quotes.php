<?php
// FIXTURE: escaping that DOES protect - the escaped value sits inside quotes in
// the query, where a quote character is the only way out and the escaping
// neutralises it. The twin of vulnerable/sql-escape-outside-quotes.php.

function quotedInterpolation($conn) {
  $user = mysqli_real_escape_string($conn, $_GET['username']);
  // EXPECT-CLEAN sql-injection
  return mysqli_query($conn, "SELECT * FROM users WHERE user = '$user';");
}

function quotedBraces($conn) {
  $user = mysqli_real_escape_string($conn, $_POST['user']);
  // EXPECT-CLEAN sql-injection
  return mysqli_query($conn, "SELECT * FROM users WHERE user = '{$user}'");
}

function quotedConcatenation($conn) {
  $name = $conn->real_escape_string($_GET['name']);
  // EXPECT-CLEAN sql-injection
  return $conn->query("SELECT * FROM users WHERE name = '" . $name . "'");
}

// quote() adds the quotes itself, so its result is safe in any position.
function pdoQuote($pdo) {
  // EXPECT-CLEAN sql-injection
  return $pdo->query("SELECT * FROM users WHERE name = " . $pdo->quote($_GET['name']));
}
