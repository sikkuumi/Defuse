<?php
// FIXTURE: escaping protects a value only INSIDE quotes in the query.
//
// mysqli_real_escape_string() puts a backslash in front of quote characters. It
// does nothing to `1 OR 1=1`, which needs no quote to break out of an unquoted
// number slot. DVWA's sqli/source/medium.php is this exact shape, and Defuse used
// to list it under "checked and cleared" - a claim of safety for a real injection.

function unquotedInterpolation($conn) {
  $id = mysqli_real_escape_string($conn, $_POST['id']);
  // EXPECT-FLOW sql-injection
  return mysqli_query($conn, "SELECT first_name FROM users WHERE user_id = $id;");
}

function unquotedConcatenation($conn) {
  $id = mysqli_real_escape_string($conn, $_GET['id']);
  $sql = "SELECT * FROM orders WHERE id = " . $id;
  // EXPECT-FLOW sql-injection
  return $conn->query($sql);
}

// A backtick quotes an identifier, and the escaping does not touch backticks.
function backtickIdentifier($conn) {
  $col = $conn->real_escape_string($_GET['sort']);
  // EXPECT-FLOW sql-injection
  return $conn->query("SELECT * FROM posts ORDER BY `$col`");
}

// Assembled by a call this engine does not read: whether the value lands inside
// quotes cannot be seen, so the line is neither cleared nor called proven.
function throughSprintf($conn) {
  $name = mysqli_real_escape_string($conn, $_GET['name']);
  $sql = sprintf("SELECT * FROM users WHERE name = '%s'", $name);
  // EXPECT-SIGNATURE sql-injection
  return mysqli_query($conn, $sql);
}
