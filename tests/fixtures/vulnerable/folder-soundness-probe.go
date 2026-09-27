// The Go half of FolderSoundnessProbe.java - an adversarial probe's programs,
// each a real injection the constant folder hid before this was fixed.
package probe

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
)

func multiAssign(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	n := 0
	n, _ = strconv.Atoi(r.URL.Query().Get("n"))
	bar := "safe"
	if n > 5 {
		bar = param
	}
	// EXPECT sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}

func redeclare(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	n := 0
	n, err := strconv.Atoi(r.URL.Query().Get("n"))
	_ = err
	bar := "safe"
	if n > 5 {
		bar = param
	}
	// EXPECT sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}

func parenAssign(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	n := 0
	(n) = len(param)
	bar := "safe"
	if n > 5 {
		bar = param
	}
	// EXPECT sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}

func addrParen(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	n := 0
	fmt.Sscan(r.URL.Query().Get("n"), &(n))
	bar := "safe"
	if n > 5 {
		bar = param
	}
	// EXPECT sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}

type limit int

func (l *limit) Set(s string) { v, _ := strconv.Atoi(s); *l = limit(v) }

func pointerReceiver(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	var n limit = 0
	n.Set(r.URL.Query().Get("n"))
	bar := "safe"
	if n > 5 {
		bar = param
	}
	// EXPECT sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}

func octal(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	perm := 0644
	bar := "safe"
	if perm < 600 {
		bar = param
	}
	// EXPECT sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}

func multiAssignSwitch(db *sql.DB, r *http.Request) {
	param := r.URL.Query().Get("p")
	mode := 1
	mode, _ = strconv.Atoi(r.URL.Query().Get("mode"))
	var bar string
	switch mode {
	case 1:
		bar = "safe"
	default:
		bar = param
	}
	// EXPECT sql-injection
	db.Query("SELECT * FROM t WHERE x = '" + bar + "'")
}
