// k02-go-closure-writes-local: A shape the constant proof read correctly when it was probed; kept so it stays that way.
// k02: the closure `set` reassigns `table` between the literal write and the query.
package main

import "database/sql"

func list(db *sql.DB, s string) {
	table := "users"
	set := func() { table = s }
	set()
	// EXPECT sql-injection
	db.Query("SELECT * FROM " + table)
}
