// FIXTURE: a prepared statement. The arguments to Exec/QueryRow are bound
// parameters, never part of the instruction - flagging them punishes the fix.
// EXPECT-NONE
package fixtures

import (
	"database/sql"
	"net/http"
)

func preparedLookup(r *http.Request, db *sql.DB) error {
	stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()
	return stmt.QueryRow(r.FormValue("id")).Scan()
}
