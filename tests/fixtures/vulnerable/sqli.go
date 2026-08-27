// FIXTURE: SQL injection, Go.
package fixtures

import (
	"database/sql"
	"fmt"
)

func findUser(db *sql.DB, id string) (*sql.Rows, error) {
	// EXPECT sql-injection
	return db.Query("SELECT * FROM users WHERE id = " + id)
}

func deleteUser(db *sql.DB, email string) (sql.Result, error) {
	// EXPECT sql-injection
	return db.Exec(fmt.Sprintf("DELETE FROM users WHERE email = '%s'", email))
}
