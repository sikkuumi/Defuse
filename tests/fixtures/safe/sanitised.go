// FIXTURE: properly sanitised flows, Go.
// EXPECT-NONE
package fixtures

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
)

func numeric(r *http.Request, db *sql.DB) {
	id, _ := strconv.Atoi(r.FormValue("id"))
	db.Query("SELECT * FROM users WHERE id = " + fmt.Sprint(id))
}

func parameterised(r *http.Request, db *sql.DB) {
	db.Query("SELECT * FROM users WHERE id = $1", r.FormValue("id"))
}

// Arguments as a list: no shell parses them.
func noShell(r *http.Request) error {
	return exec.Command("ping", "-c", "1", r.FormValue("host")).Run()
}
