<?php
// EXPECT-NONE
//
// PUNISHING THE FIX, SEVENTH TIME - AND THE ONLY ONE STILL ON THE SCOREBOARD.
//
// DVWA ships four variants of each vulnerability: low, medium, high, and
// `impossible.php`, which is the author's deliberate FIX. Our scorer reports
// "fix respected: 75%" for exactly one reason - `exec/impossible.php` is still
// flagged for command injection. It has been the single red mark in the
// instrument panel for weeks.
//
// The code it flags is this, reduced below: DVWA splits an IP address on dots,
// checks that all four octets are numeric, and only then rebuilds the string
// and pings it. There is no possible shell metacharacter in the result. A
// value that `is_numeric()` accepted cannot contain a semicolon.
//
// WHY THE TRACER MISSED IT. Every previous fix in this project was a
// SANITISER - a function that takes a dirty value and returns a clean one:
//
//     $safe = esc_html($dirty);          // transforms
//
// This is a different shape entirely. `is_numeric` transforms nothing. It
// returns a boolean, and the cleanliness lives in the CONTROL FLOW - inside
// the true-branch, and only there, the value is known to be digits. The
// engine's whole sanitiser model is value-in/value-out, so a guard was
// invisible to it.
//
// HOW NARROW THIS HAS TO BE, because a guard rule is a silencing rule and this
// project has over-corrected before (the lowercase-word rejection that dropped
// the corpus 48 to 32; the mathjs.eval regression caught only by dvna's flow
// count falling 3 to 2). A guard only counts when being TRUE proves the value
// holds no dangerous character. That is a very short list - is_numeric,
// ctype_digit, ctype_alnum, is_int and their siblings - and it does NOT
// include the guards that look reassuring and prove nothing:
//
//     if (strlen($x) < 100)     a hundred characters of `;rm -rf /` fits fine
//     if ($x !== '')            proves only that something is there
//     if (isset($x))            proves only that it exists
//
// Those still report, and the vulnerable counterpart holds them.

function ping_the_host( $ip ) {
	// THE DVWA SHAPE. Split, check every octet is numeric, rebuild, execute.
	// The value reaching shell_exec is assembled from four values that each
	// passed is_numeric, so it is digits and dots by construction.
	$target = stripslashes( $ip );
	$octet  = explode( '.', $target );

	if ( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) )
		&& ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) )
		&& ( sizeof( $octet ) == 4 ) ) {
		$target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];
		return shell_exec( 'ping -c 4 ' . $target );
	}

	return 'ERROR: You have entered an invalid IP.';
}

function ctype_guarded( $page ) {
	// ctype_digit is the stricter cousin - it rejects "1e5" and " 12", which
	// is_numeric accepts. Both are safe here; neither can carry a metacharacter.
	if ( ctype_digit( $page ) ) {
		return shell_exec( 'sed -n ' . $page . 'p /var/log/app.log' );
	}
	return '';
}

function alnum_guarded( $name ) {
	// Letters and digits only. No quote, no angle bracket, no semicolon - so
	// this is safe for the page as well as for the shell.
	if ( ctype_alnum( $name ) ) {
		echo '<h1>Hello ' . $name . '</h1>';
	}
}

function int_guarded( $id ) {
	// The value is proven an integer before it reaches the query.
	if ( is_int( $id ) ) {
		$conn = new mysqli( 'localhost', 'u', 'p', 'db' );
		return $conn->query( 'SELECT * FROM users WHERE id = ' . $id );
	}
	return null;
}

// STILL REPORTED, and deliberately not in this file: the same four functions
// with the guard removed, and the three reassuring-but-useless guards listed
// above. See vulnerable/weak-guard.php. If the rule added here also silences
// those, this fixture passing means nothing.
