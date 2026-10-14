// k05-go-for-init-shadow: A shape the constant proof read correctly when it was probed; kept so it stays that way.
// k05: the function parameter `table` is shadowed only inside the for loop.
package main

import "database/sql"

func list(db *sql.DB, table string) {
	for table := "users"; table != ""; table = "" {
		db.Query("SELECT * FROM " + table)
	}
	// EXPECT sql-injection
	db.Query("SELECT * FROM " + table)
}
