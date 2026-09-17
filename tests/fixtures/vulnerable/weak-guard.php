<?php
// FIXTURE: the falsification half of safe/validated-guard.php.
//
// That file teaches the engine that a value checked by `is_numeric()` is safe
// inside the branch the check guards. This file is the fence around that
// lesson, and it matters more than the lesson does: a guard rule is a SILENCING
// rule, and silence is the one failure this scanner cannot detect in itself.
//
// Two ways the rule could go wrong, and both are here.

// ---- 1. GUARDS THAT PROVE NOTHING ----
//
// These read like validation and are not. Being inside their true-branch tells
// you the value exists, or is short, or is non-empty. None of that stops a
// semicolon.

function length_is_not_validation( $host ) {
	if ( strlen( $host ) < 100 ) {
		// EXPECT command-injection
		return shell_exec( 'ping -c 4 ' . $host );
	}
	return '';
}

function isset_is_not_validation( $host ) {
	if ( isset( $host ) && $host !== '' ) {
		// EXPECT command-injection
		return shell_exec( 'ping -c 4 ' . $host );
	}
	return '';
}

function nonempty_is_not_validation( $name ) {
	if ( ! empty( $name ) ) {
		// EXPECT xss
		echo '<h1>Hello ' . $name . '</h1>';
	}
}

// ---- 2. THE RIGHT GUARD, THE WRONG VALUE OR THE WRONG PLACE ----
//
// This is the subtler half, and it is the same mistake the Jenkins escaper bug
// made: a check that covers ONE value silencing a DIFFERENT one that happens to
// sit nearby.

function guard_covers_a_different_value( $port, $host ) {
	// `$port` is validated. `$host` is not, and `$host` is what carries the
	// attacker's semicolon.
	if ( is_numeric( $port ) ) {
		// EXPECT command-injection
		return shell_exec( 'nc ' . $host . ' ' . $port );
	}
	return '';
}

function guard_does_not_reach_here( $host ) {
	// The check happened, and the dangerous call is OUTSIDE the branch it
	// guards. Being checked somewhere in the file proves nothing about here.
	if ( is_numeric( $host ) ) {
		echo 'looks like a number';
	}
	// EXPECT command-injection
	return shell_exec( 'ping -c 4 ' . $host );
}

function guard_is_negated( $host ) {
	// Inside THIS branch the value is known NOT to be numeric - which is the
	// exact opposite of safe. A rule that matches on the call text alone,
	// without reading the branch it landed in, would get this backwards.
	if ( ! is_numeric( $host ) ) {
		// EXPECT command-injection
		return shell_exec( 'ping -c 4 ' . $host );
	}
	return '';
}
