// The Go half of joined-constant.js: literals joined with `+` are fixed.
// In safe/, any finding is a failure.
package fixtures

import "database/sql"

func archived(db *sql.DB) {
	base := "users"
	table := base + "_archive"
	db.Query("SELECT * FROM " + table)
}
