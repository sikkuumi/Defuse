// g02-method-receiver: `t` is the method receiver - input - which the proof did not count as a parameter.
// g02: `t` is the method receiver - input - and is only overwritten when !ok.
package main

import "database/sql"

type Table string

func (t Table) List(db *sql.DB, ok bool) {
	if !ok {
		t = "users"
	}
	// EXPECT sql-injection
	q := "SELECT * FROM " + t
	db.Query(string(q))
}
