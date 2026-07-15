//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/about" {
			fmt.Fprint(w, "about page from real backend")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":         true,
			"path":       r.URL.Path,
			"query":      r.URL.RawQuery,
			"method":     r.Method,
			"protected":  r.Header.Get("X-Protected-By"),
			"waf_status": r.Header.Get("X-WAF-Status"),
			"time":       time.Now().Format(time.RFC3339),
		})
	})
	fmt.Println("lab backend listening on :9000")
	if err := http.ListenAndServe(":9000", handler); err != nil {
		panic(err)
	}
}
