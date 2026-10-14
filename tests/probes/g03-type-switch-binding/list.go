// g03-type-switch-binding: `switch t := v.(type)` binds a new `t`: inside the case it is v, not the outer literal.
// g03: inside the type switch, `t` is the switch's own binding (v as a string), not the "users" local.
package main

import (
	"database/sql"
	"log"
)

func list(db *sql.DB, v interface{}) {
	t := "users"
	log.Println(t)
	switch t := v.(type) {
	case string:
		// EXPECT sql-injection
		db.Query("SELECT * FROM " + t)
	}
}
