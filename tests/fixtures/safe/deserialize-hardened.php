<?php
// EXPECT-NONE
//
// Both of these are the SAME dangerous call with a restriction added. Reporting
// a hardened call teaches people that hardening does not help, which is the
// worst thing an injection rule can do.
function restored() {
  return unserialize($_COOKIE['session'], ['allowed_classes' => false]);
}

// json_decode returns plain arrays and strings. It cannot name a class, so it
// cannot start a gadget chain, and it is deliberately absent from the rule.
function decoded() {
  return json_decode($_COOKIE['session'], true);
}
