<?php
// EXPECT-NONE
//
// Every flow here reaches a real sink and is washed on the way. If any of them
// reports, a sanitiser stopped being recognised.

function shown() {
  echo htmlspecialchars($_GET['name']);
}

function counted($conn) {
  $page = intval($_GET['page']);
  return $conn->query("SELECT * FROM posts LIMIT " . $page);
}

function pinged() {
  system("ping -c 1 " . escapeshellarg($_GET['host']));
}

// A fixed query with nothing spliced in is not a finding, however it is written.
function constant($conn) {
  return $conn->query("SELECT id, name FROM users ORDER BY name");
}
