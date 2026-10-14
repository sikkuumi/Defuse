// g05r-block-shadow-package-var: As g05, with a dead branch so the withdrawal leaves a receipt.
// g05r: the "users" `table` is local to the if block; the query reads the package-level var from config.go.
package main

import (
	"database/sql"
	"log"
)

func list(db *sql.DB, verbose bool) {
	if verbose {
		table := "users"
		if 1 > 2 {
			table = "accounts"
		}
		log.Println(table)
	}
	// EXPECT sql-injection
	db.Query("SELECT * FROM " + table)
}
