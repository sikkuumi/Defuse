// g06-select-receive-binding: `case t := <-ch` binds a new `t` from the channel.
// g06: inside the select case, `t` is the value received from ch, not the "users" local.
package main

import (
	"database/sql"
	"log"
)

func list(db *sql.DB, ch chan string) {
	t := "users"
	log.Println(t)
	select {
	case t := <-ch:
		// EXPECT sql-injection
		db.Query("SELECT * FROM " + t)
	}
}
