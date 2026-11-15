<?php
// FIXTURE: path traversal (CWE-22) in PHP. DVWA's "File Inclusion" page reads
// whatever `page` names; these are the calls such pages use to read it.

function show() {
  // EXPECT-FLOW path-traversal
  readfile('pages/' . $_GET['page']);
}

function save() {
  // EXPECT-FLOW path-traversal
  file_put_contents("/var/notes/{$_POST['name']}.txt", $_POST['body']);
}

// PHP cuts every folder off an upload's name before the script sees it, so
// this is an unrestricted upload (CWE-434), not path traversal. The other
// field of the same upload is a request value like any other.
function store() {
  move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);
  // EXPECT-FLOW path-traversal
  move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_POST['dir'] . '/x.png');
  // EXPECT-FLOW path-traversal
  unlink('uploads/' . $_POST['old']);
}

function drop() {
  // EXPECT-FLOW path-traversal
  unlink('/tmp/cache/' . $_REQUEST['key']);
}
