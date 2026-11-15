<?php
// FIXTURE: the fixes for path traversal in PHP, which must stay quiet.
// unlink, not readfile: readfile also reads URLs, which the SSRF rule asks about.

function drop() {
  $name = basename($_GET['name']);
  // EXPECT-CLEAN path-traversal
  unlink('cache/' . $name);
}

function dropInvoice() {
  $id = intval($_GET['id']);
  // EXPECT-CLEAN path-traversal
  unlink("invoices/{$id}.pdf");
}
