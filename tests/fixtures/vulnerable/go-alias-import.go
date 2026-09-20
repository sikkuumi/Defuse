// THE ALIASED-IMPORT LIMITATION IS REAL, BUT NOT WHERE THE NOTE SAID IT WAS.
//
// The Go taint coverage note used to end:
//
//   "...and a package imported under an alias is matched by the alias, not the
//    real package."
//
// Written as a general property of Go imports. Testing it found that the taint
// sinks do not behave that way at all: `sh.Command(...)` and
// `runner.Command(...)` are both found, in files where the name `exec` appears
// nowhere, because the command sink is matched on the METHOD name rather than
// on the package text.
//
// Where the limitation is real is weak-hash, which IS matched by receiver
// package text - and that rule's own support note says so precisely. The taint
// note had generalised a specific, accurate statement into a broad, wrong one.
//
// That is a small thing to get wrong and exactly the kind of thing this
// project cannot afford to get wrong, because the notes are the product. A
// limitation nobody tested drifted into claiming more territory than it had,
// and it took writing the fixture to notice. The note is now narrower, and
// this file is why.
package main

import (
	"crypto/md5"
	"net/http"
	sh "os/exec"

	hasher "crypto/sha1"
)

// The alias, traced anyway. The package name `exec` does not appear in this
// file and the finding is still made.
func aliasedCommandIsFound(r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	// EXPECT-FLOW command-injection
	sh.Command("sh", "-c", cmd).Run()
}

// The unaliased weak hash, found - matched on the receiver text `md5`.
func plainWeakHashIsFound(b []byte) {
	// EXPECT weak-hash
	md5.New().Write(b)
}

// The aliased weak hash. A GENUINE MISS, unannotated on purpose.
//
// Identical danger to the line above, and silent, because `hasher` is not a
// package name this rule recognises. This is the case the limitation was
// always about, and the one worth fixing if import resolution ever gets built.
func aliasedWeakHashIsMissed(b []byte) {
	hasher.Sum(b)
}
