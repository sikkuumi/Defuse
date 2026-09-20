// GO'S MULTI-VALUE ASSIGNMENT, MEASURED INSTEAD OF DESCRIBED.
//
// The Go coverage note says multi-value assignments "bind only when the two
// sides line up". It was true and untested, which means nobody would have
// noticed it getting worse - or getting better, leaving the note apologising
// for something already fixed.
//
// `a, b := f()` is not an edge case in Go. It is how every function that can
// fail returns, so it is the shape a value takes on its way out of most real
// calls, and a taint engine that loses values there loses them everywhere.
//
// The tracer binds EVERY name on the left to the same taint. That is
// deliberate, and it is imprecise in one direction only: it over-claims WHICH
// of the returned names is dirty, and never under-claims whether the data is
// attacker-controlled. These cases pin where that lands.
package main

import (
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
)

// The everyday shape: a value and an error, from a call that takes taint in.
func valueAndError(r *http.Request) {
	dir, err := url.QueryUnescape(r.URL.Query().Get("dir"))
	_ = err
	// EXPECT-FLOW command-injection
	exec.Command("sh", "-c", "ls "+dir).Run()
}

// Taint through a command's own output, rebound by a multi-value assignment.
func throughCommandOutput(r *http.Request) {
	out, err := exec.Command("echo", r.URL.Query().Get("msg")).Output()
	_ = err
	// EXPECT-FLOW command-injection
	exec.Command("sh", "-c", string(out)).Run()
}

// THE IMPRECISION, STATED RATHER THAN HIDDEN.
//
// `err` is bound dirty too, because the tracer cannot tell which of the two
// returned names carried the value. Reporting this is the over-claim the note
// warns about: the data really did come from the request, but the specific
// name being used here is the error, not the output.
//
// It is annotated EXPECT-FLOW because that is what the engine does, not
// because it is ideal. Writing EXPECT-NONE here would be describing a tracer
// we do not have, and the fixture's job is to record the one we do.
func theErrorIsBoundDirtyToo(r *http.Request) {
	out, err := exec.Command("echo", r.URL.Query().Get("msg")).Output()
	_ = out
	// EXPECT-FLOW command-injection
	exec.Command("sh", "-c", err.Error()).Run()
}

// The control: numeric conversion is a sanitiser. Atoi returns an int, and an
// int cannot be a shell command whatever the attacker typed. Unannotated - if
// this fires, numeric conversion stopped counting.
func numericConversionCleans(r *http.Request) {
	n, err := strconv.Atoi(r.URL.Query().Get("n"))
	_ = err
	exec.Command("sleep", strconv.Itoa(n)).Run()
}
