// g05-block-shadow-package-var: The literal `table` is a block-local `:=`; the read after the block is the package variable.
// g05: the "users" `table` is local to the if block; the query reads the package-level var from config.go.
package main

import (
	"database/sql"
	"log"
)

func list(db *sql.DB, verbose bool) {
	if verbose {
		table := "users"
		log.Println(table)
	}
	// EXPECT sql-injection
	db.Query("SELECT * FROM " + table)
}
