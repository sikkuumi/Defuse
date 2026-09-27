// The Go half of FolderSoundness.java. `n := 0` is the only `=`-style write to
// n in each function, and in each one n changes anyway:
//
//   scanned      &n hands the address to Sscan, which writes the input into it
//   incremented  n++ writes without an `=`
//
// The folder read n as 0, declared `n > 5` false, dropped the arm that reads
// the request, and the SQL rule withdrew its guess as "provably constant".

package fixtures

import (
	"database/sql"
	"fmt"
	"net/http"
)

func scanned(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	n := 0
	fmt.Sscan(param, &n)
	bar := "safe"
	if n > 5 {
		bar = param
	}
	// EXPECT-FLOW sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}

func incremented(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	n := 0
	if param == "" {
		n++
	}
	bar := "safe"
	if n > 0 {
		bar = param
	}
	// EXPECT-FLOW sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}
