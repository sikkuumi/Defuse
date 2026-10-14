// g02r-method-receiver: As g02, with a dead branch so the withdrawal leaves a receipt.
// g02r: `t` is the method receiver - input - and is only overwritten when !ok.
package main

import "database/sql"

type Table string

func (t Table) List(db *sql.DB, ok bool) {
	if !ok {
		t = "users"
	}
	if 1 > 2 {
		t = "accounts"
	}
	// EXPECT sql-injection
	q := "SELECT * FROM " + t
	db.Query(string(q))
}
