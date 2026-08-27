// FIXTURE (cross-file): the sink lives here. Same package as xfile_handler.go.
package fixtures

import "database/sql"

func runQueryXF(db *sql.DB, sqlText string) {
	// EXPECT-FLOW sql-injection
	db.Query(sqlText)
}
