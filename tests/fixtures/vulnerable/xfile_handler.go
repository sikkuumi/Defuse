// FIXTURE (cross-file): the source lives here.
package fixtures

import (
	"database/sql"
	"net/http"
)

func handlerXF(r *http.Request, db *sql.DB) {
	runQueryXF(db, "SELECT * FROM users WHERE id = "+r.FormValue("id"))
}
