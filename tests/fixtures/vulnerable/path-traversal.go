// FIXTURE: path traversal (CWE-22) in Go.
package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func read(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// EXPECT-FLOW path-traversal
	data, _ := os.ReadFile("/srv/reports/" + name)
	w.Write(data)
}

// filepath.Clean("../../etc/passwd") is still "../../etc/passwd".
func serve(w http.ResponseWriter, r *http.Request) {
	file := filepath.Join("/srv/static", filepath.Clean(r.FormValue("f")))
	// EXPECT-FLOW path-traversal
	http.ServeFile(w, r, file)
}

func remove(w http.ResponseWriter, r *http.Request) {
	// EXPECT-FLOW path-traversal
	os.Remove("/tmp/uploads/" + r.FormValue("id"))
}
