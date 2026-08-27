// FIXTURE: the SAFE versions, Go.
// EXPECT-NONE
package fixtures

import (
	"crypto/sha256"
	"database/sql"
	"os"
	"os/exec"
)

func findUser(db *sql.DB, id string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE id = $1", id)
}

var dbPassword = os.Getenv("DB_PASSWORD")

func fingerprint(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func ping(host string) error {
	return exec.Command("ping", "-c", "1", host).Run()
}
