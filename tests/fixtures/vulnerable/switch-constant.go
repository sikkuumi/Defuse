// A SWITCH IN GO: A HOLE FIRST, THEN THE FOLDING.
//
// THE HOLE. The tracer keeps a value's taint when a clean write might not
// happen - a clean write inside an `if` does not erase anything. It knows that
// by a list of node types that mean "this might not run", and Go's switch was
// not on the list. So a clean write in ANY case of a Go switch wiped the taint,
// as if every case always ran:
//
//     bar := r.URL.Query().Get("q")
//     switch len(bar) { case 1: bar = "safe" }
//     exec.Command("sh", "-c", bar)       // reported as NOTHING
//
// The identical logic written as an `if` was reported. Found while writing this
// file, by trying the Go spelling before assuming it behaved like the others.
//
// THE FOLDING. Go does not fall through: a case ends at its last statement
// unless that statement is `fallthrough`. A folder that borrowed C's rule would
// run case 2 after case 1 below and call a live flow clean.

package fixtures

import (
	"database/sql"
	"net/http"
	"os/exec"
)

// ---------------------------------------------------------------- THE HOLE

func cleanWriteInOneCase(w http.ResponseWriter, r *http.Request) {
	bar := r.URL.Query().Get("q")
	switch len(bar) {
	case 1:
		bar = "safe"
	}
	// EXPECT-SIGNATURE command-injection
	exec.Command("sh", "-c", bar).Run()
}

// ---------------------------------------------------------------- DECIDED

func deadCase(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	mode := 2
	var bar string
	switch mode {
	case 1:
		bar = param
	case 2:
		bar = "constant"
	}
	// EXPECT-CLEAN sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}

// Case 1 runs and ENDS - Go does not fall into case 2.
func liveCaseNoFallthrough(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	mode := 1
	var bar string
	switch mode {
	case 1:
		bar = param
	case 2:
		bar = "constant"
	}
	// EXPECT-FLOW sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}

// ---------------------------------------------------------------- THE FENCE

// `fallthrough` is Go's explicit opt-in, and case 3 runs after case 2 here.
func explicitFallthrough(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	mode := 2
	var bar string
	switch mode {
	case 2, 4:
		bar = "constant"
		fallthrough
	case 3:
		bar = param
	default:
		bar = "other"
	}
	// EXPECT-FLOW sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}
