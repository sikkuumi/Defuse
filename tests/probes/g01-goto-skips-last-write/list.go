// g01-goto-skips-last-write: goto jumps over the literal write, so the earlier unknown value is the one read.
// g01: `goto run` jumps over `table = "users"`, so the query reads the looked-up value.
package main

import "database/sql"

func list(db *sql.DB) {
	table := lookup("t")
	goto run
	table = "users"
run:
	// EXPECT sql-injection
	db.Query("SELECT * FROM " + table)
}
