<?php
// FIXTURE: one escaped value and one raw value in the same expression.
//
// THIS CRASHED A SCAN. Adding the PHP page-buffer sink and pointing it at
// WordPress killed the whole run on the engine's own invariant:
//
//   internal error: flowVerifiedFinding: path contains a sanitiser
//   (passed through `esc_url()`) - that is a CLEAN flow, not a verified
//   vulnerability.
//
// The invariant was right to fire and right to crash rather than publish a
// proof it could not support. The PATH was what was wrong: two tainted values
// merge in this expression, `esc_url($u)` is escaped and `$label` is not, and
// the merged step list carried the escaper from the OTHER contributor. One
// narrative assembled out of two different values' histories.
//
// A sanitiser step now only stays a sanitiser when the value that actually
// reached the sink went through it. Otherwise the path says so in words.
//
// The finding here is REAL - `$label` is raw - so this belongs in vulnerable/,
// not in safe/. See safe/wordpress-escapers.php for the all-escaped form,
// which must still stay quiet.

function link_row($u, $label) {
	// EXPECT-FLOW xss
	$html = '<a href="' . esc_url($u) . '">' . $label . '</a>';
	return $html;
}

function reflected() {
	$label = $_GET['label'];
	return link_row('https://example.com', $label);
}
