<?php
// FIXTURE: PHP's superglobals are attacker input by specification - there is no
// framework convention to guess at, which is what makes PHP flows unusually
// certain compared with the other four languages.

function byId($conn) {
  $id = $_GET['id'];
  $sql = "SELECT * FROM users WHERE id = " . $id;
  // EXPECT-FLOW sql-injection
  return $conn->query($sql);
}

// Interpolation, not concatenation. Identical to a database.
function search($conn) {
  // EXPECT-FLOW sql-injection
  return mysqli_query($conn, "SELECT * FROM posts WHERE title = '{$_POST['q']}'");
}

// A prepared statement whose SQL was concatenated is not parameterised.
function prep($pdo) {
  // EXPECT-FLOW sql-injection
  $stmt = $pdo->prepare("DELETE FROM logs WHERE owner = " . $_REQUEST['who']);
  return $stmt;
}
