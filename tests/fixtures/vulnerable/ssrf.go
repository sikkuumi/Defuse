// FIXTURE: server-side request forgery, Go.
package fixtures

import (
	"context"
	"net/http"
)

func proxy(w http.ResponseWriter, r *http.Request) {
	// EXPECT-FLOW ssrf
	resp, _ := http.Get(r.URL.Query().Get("u"))
	defer resp.Body.Close()
}

func forward(w http.ResponseWriter, r *http.Request) {
	// EXPECT-FLOW ssrf
	req, _ := http.NewRequest("GET", r.FormValue("u"), nil)
	http.DefaultClient.Do(req)
}

func forwardCtx(ctx context.Context, r *http.Request) {
	// EXPECT-FLOW ssrf
	req, _ := http.NewRequestWithContext(ctx, "GET", r.FormValue("u"), nil)
	http.DefaultClient.Do(req)
}

// A fixed start of the address pins the host: to review, not proven.
func item(w http.ResponseWriter, r *http.Request) {
	// EXPECT-SIGNATURE ssrf
	resp, _ := http.Get("https://api.example.com/items/" + r.FormValue("id"))
	defer resp.Body.Close()
}

func status() {
	resp, _ := http.Get("https://api.example.com/status") // SAFE
	defer resp.Body.Close()
}
