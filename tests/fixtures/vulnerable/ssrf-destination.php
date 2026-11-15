<?php
// FIXTURE: a fixed start to the address pins where the request goes.
// DVWA's view_source_all.php and view_help.php, where an AI review called all
// eight proven SSRF findings wrong: `./` and `../` keep the read on local disk.
// On local disk, `../` in that id is path traversal, and is proven as that.
// The `http://` start in status() makes it a URL: no path finding there.

function viewSource() {
  // EXPECT-SIGNATURE ssrf
  // EXPECT-FLOW path-traversal
  $source = file_get_contents("./{$_GET['id']}/source/low.php");
  return strlen($source);
}

function viewHelp() {
  // EXPECT-SIGNATURE ssrf
  // EXPECT-FLOW path-traversal
  $help = file_get_contents('../' . "vulnerabilities/{$_GET['id']}/help/help.php");
  return strlen($help);
}

// The whole address is the attacker's: real SSRF.
function proxy() {
  // EXPECT-FLOW ssrf
  // EXPECT-FLOW path-traversal
  // (`../` in it reads any file, not only a URL: both bugs live on this line)
  $page = file_get_contents($_GET['url']);
  return strlen($page);
}

// The attacker writes the host.
function status() {
  // EXPECT-FLOW ssrf
  $page = file_get_contents("http://" . $_GET['host'] . "/status");
  return strlen($page);
}
