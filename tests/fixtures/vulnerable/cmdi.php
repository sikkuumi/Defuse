<?php
function ping() {
  // EXPECT-FLOW command-injection
  system("ping -c 1 " . $_GET['host']);
}

function archive() {
  $name = $_POST['file'];
  // EXPECT-FLOW command-injection
  shell_exec("tar -czf out.tgz $name");
}
