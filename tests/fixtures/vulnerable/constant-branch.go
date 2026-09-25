// GO IS THE SECOND CONTROL, AND IT CONTROLS FOR A DIFFERENT THING.
//
// See constant-branch.py for the story and constant-branch.js for why a passing
// control earns a file. JavaScript shares Java's field names on both the
// ternary and the `if`, so it tests that the folder is not Java-specific. Go
// has no ternary at all - the language deliberately does not have one - so it
// tests the OTHER half on its own: the statement walker that refuses to descend
// into a branch that cannot run, and the underCondition rule that stops calling
// a decidably-true `if` a condition.
//
// That separation is the point. If a change ever breaks the ternary path and
// leaves the statement path working, JavaScript would fail and Go would pass;
// if it breaks the statement path, Go fails too. Two files that fail for
// different reasons tell you where to look, and one file that covers both does
// not.
//
// Go also writes its `if` without parentheses, so the condition is a bare
// binary_expression rather than the parenthesized wrapper Java and the C family
// hand over. The folder unwraps single-child nodes to cope with that; here the
// unwrapping simply is not needed, which is its own small assurance.
package fixtures

import (
	"database/sql"
	"net/http"
)

// ---------------------------------------------------------------- DEAD BRANCHES

func ifElseDeadArm(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	num := 106
	var bar string
	if (7*18)+num > 200 {
		bar = "constant"
	} else {
		bar = param
	}
	// EXPECT-CLEAN sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}

func deadThenArm(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	var bar string
	if 1 > 2 {
		bar = param
	} else {
		bar = "constant"
	}
	// EXPECT-CLEAN sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}

func neverTaken(db *sql.DB, r *http.Request) {
	bar := "constant"
	if false {
		bar = r.URL.Query().Get("p")
	}
	// EXPECT-CLEAN sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}

// ------------------------------------------------------------------ LIVE BRANCHES

func ifLiveArm(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	var bar string
	if 1 < 2 {
		bar = param
	} else {
		bar = "constant"
	}
	// EXPECT-FLOW sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}

func undecidableCondition(db *sql.DB, r *http.Request) {
	bar := "constant"
	if r.URL.Query().Get("mode") == "raw" {
		bar = r.URL.Query().Get("p")
	}
	// EXPECT-FLOW sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}
