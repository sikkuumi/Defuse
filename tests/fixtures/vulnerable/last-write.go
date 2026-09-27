// A shadowing := in an inner block, and a closure that writes the name: neither
// makes the outer "safe" write certain at the query.

package fixtures

import (
	"database/sql"
	"net/http"
)
func shadow(db *sql.DB, r *http.Request) {
	bar := r.URL.Query().Get("p")
	if len(bar) > 0 {
		bar := "safe"
		_ = bar
	}
	// EXPECT sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}
func deferWrite(db *sql.DB, r *http.Request) {
	bar := "safe"
	func() { bar = r.URL.Query().Get("p") }()
	// EXPECT sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}
