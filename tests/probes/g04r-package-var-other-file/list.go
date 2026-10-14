// g04r-package-var-other-file: As g04, with a dead branch so the withdrawal leaves a receipt.
// g04r: `table` is a package-level var declared in config.go; the first query reads it before this function assigns "users".
package main

import "database/sql"

func list(db *sql.DB) {
	// EXPECT sql-injection
	db.Query("SELECT * FROM " + table)
	table = "users"
	if 1 > 2 {
		table = "accounts"
	}
}
