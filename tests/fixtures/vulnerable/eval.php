<?php
function calc() {
  // EXPECT-FLOW code-injection
  return eval($_GET['expr']);
}
function checked() {
  // EXPECT-FLOW code-injection
  assert($_POST['cond']);
}
function safe() {
  return eval('return 1 + 1;');                 // SAFE: constant
}
