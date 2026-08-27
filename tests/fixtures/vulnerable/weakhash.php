<?php
function fingerprint($x) {
  // EXPECT weak-hash
  return md5($x);
}

function legacy($x) {
  // EXPECT weak-hash
  return hash("sha1", $x);
}
