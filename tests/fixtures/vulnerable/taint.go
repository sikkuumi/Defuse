// FIXTURE: verified data flows, Go (net/http + database/sql).
package fixtures

import (
	"database/sql"
	"net/http"
	"os/exec"
)

func throughAVariable(r *http.Request, db *sql.DB) {
	id := r.FormValue("id")
	query := "SELECT * FROM users WHERE id = " + id
	// EXPECT-FLOW sql-injection
	db.Query(query)
}

func intoAShell(r *http.Request) error {
	// EXPECT-FLOW command-injection
	return exec.Command("sh", "-c", "ping -c 1 "+r.FormValue("host")).Run()
}

func buildQuery(value string) string {
	return "SELECT * FROM users WHERE name = '" + value + "'"
}

func acrossFunctions(r *http.Request, db *sql.DB) {
	// EXPECT-FLOW sql-injection
	db.Query(buildQuery(r.FormValue("q")))
}
