// EXPECT-NONE
//
// THE LAST INSTANCE OF THE SCOPING CLASS.
//
// Six false positives this month were one bug wearing six names: a sink
// matching a common method name with nothing said about the receiver. Five of
// them were fixed by naming the receiver. This one could not be, and survived
// an entire scoping sweep because of it:
//
//     fmt.Fprintf(w, format, args...)
//
// writes to `w`, and the RECEIVER is `fmt`. Widening the receiver pattern to
// keep real response writes firing is what kept a test mock's
// `fmt.Fprintf(out, "%s: %s\n", name, value)` reported as cross-site scripting
// in gitea, twice, through two rounds of fixes.
//
// So the destination is now checked where it actually is - argument zero - and
// argument zero is excluded from the payload check, because the writer is where
// output goes rather than what is written. The declared type decides:
// http.ResponseWriter is a page, bytes.Buffer is not.

package fixtures

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
)

func writeToBuffer(r *http.Request) string {
	name := r.FormValue("name")
	var buf bytes.Buffer
	// A buffer. Nobody's browser reads this.
	fmt.Fprintf(&buf, "<b>%s</b>", name)
	buf.WriteString("<i>" + name + "</i>")
	return buf.String()
}

func writeToFile(r *http.Request, f *os.File) {
	name := r.FormValue("name")
	// A file on disk, and stderr. Neither parses HTML.
	fmt.Fprintf(f, "<record>%s</record>\n", name)
	fmt.Fprintf(os.Stderr, "warning: <%s> not found\n", name)
}

func writeToHash(r *http.Request) []byte {
	name := r.FormValue("name")
	digest := sha256.New()
	// Bytes in, digest out.
	digest.Write([]byte("<x>" + name + "</x>"))
	return digest.Sum(nil)
}

// STILL REPORTED, and deliberately not in this file: the same call with an
// http.ResponseWriter as its destination. See vulnerable/xss.go - if the guard
// added here also silences that, this fixture passing means nothing.
