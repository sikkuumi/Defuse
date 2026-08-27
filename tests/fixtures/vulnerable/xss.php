<?php
// `echo` is a statement, not a call or an assignment - the shape layer routes it
// through the assign-sink path with the keyword standing in as the property.

function greet() {
  // EXPECT-FLOW xss
  echo "<h1>Hello " . $_GET['name'] . "</h1>";
}

function show() {
  $bio = $_POST['bio'];
  // EXPECT-FLOW xss
  printf("<p>%s</p>", $bio);
}
