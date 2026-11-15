// FIXTURE: the fixes for path traversal in Go, which must stay quiet.
package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

func read(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("name"))
	// EXPECT-CLEAN path-traversal
	data, _ := os.ReadFile(filepath.Join("/srv/reports", name))
	w.Write(data)
}

func invoice(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.FormValue("id"))
	// EXPECT-CLEAN path-traversal
	data, _ := os.ReadFile("/srv/invoices/" + strconv.Itoa(id) + ".pdf")
	w.Write(data)
}
