<?php
// FIXTURE: a key handed straight to the function that uses it, in PHP.
function sign($data) {
  // EXPECT-SIGNATURE hardcoded-secret
  return hash_hmac('sha256', $data, 'k3y-written-in-the-code');
}
