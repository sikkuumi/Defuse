// `+=` EXTENDS A VALUE. FOR A LONG TIME IT REPLACED IT.
//
// See append-assign.js for the full story. Go is worth its own fixture because
// it spells compound assignment as assignment_statement with a `+=` operator -
// the same node it uses for a plain `=`, unlike JavaScript and Python which
// have a distinct augmented node. The fix reads the operator field rather than
// the node type precisely so that this difference stops mattering, and this
// file is what proves it stopped mattering.
package main

import (
	"net/http"
	"os/exec"
)

func trailingConstant(r *http.Request) {
	cmd := "ls "
	cmd += r.URL.Query().Get("dir")
	cmd += " -l"
	// EXPECT-FLOW command-injection
	exec.Command("sh", "-c", cmd).Run()
}

func leadingConstant(r *http.Request) {
	cmd := "grep "
	cmd += "-F "
	cmd += r.URL.Query().Get("term")
	// EXPECT-FLOW command-injection
	exec.Command("sh", "-c", cmd).Run()
}

// The over-fix guard: a real overwrite must still clear the value.
func realReassignmentStillClears(r *http.Request) {
	cmd := "ls "
	cmd += r.URL.Query().Get("dir")
	cmd = "ls -l"
	exec.Command("sh", "-c", cmd).Run()
}
