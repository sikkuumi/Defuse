// g04-package-var-other-file: `table` is a package variable declared in config.go, set there from an unknown value.
// g04: `table` is a package-level var declared in config.go; the first query reads it before this function assigns "users".
package main

import "database/sql"

func list(db *sql.DB) {
	// EXPECT sql-injection
	db.Query("SELECT * FROM " + table)
	table = "users"
}
