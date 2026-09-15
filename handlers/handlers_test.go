package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"rhinowaf/waf"
)

// a form POST used to reach the backend with an empty body (502 from the
// content-length mismatch), and the path got html-escaped / keyword-stripped
func TestProxyPassesRequestThroughIntact(t *testing.T) {
	var gotPath, gotQuery, gotBody, gotAuth string
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotPath, gotQuery, gotBody, gotAuth = r.URL.Path, r.URL.RawQuery, string(b), r.Header.Get("Authorization")
		w.WriteHeader(204)
	}))
	defer be.Close()
	if err := Configure(be.URL, 10); err != nil {
		t.Fatal(err)
	}
	h := waf.AdaptiveProtect(Home)

	req := httptest.NewRequest("POST", "/update-profile?b=2&a=1", strings.NewReader("user=bob&msg=hello+world"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0")
	req.Header.Set("Authorization", "Bearer tok0x1f--abc")
	req.RemoteAddr = "203.0.113.9:1234"
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != 204 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if gotPath != "/update-profile" || gotQuery != "b=2&a=1" {
		t.Fatalf("path/query mangled: %q %q", gotPath, gotQuery)
	}
	if gotBody != "user=bob&msg=hello+world" {
		t.Fatalf("body mangled: %q", gotBody)
	}
	if gotAuth != "Bearer tok0x1f--abc" {
		t.Fatalf("auth header mangled: %q", gotAuth)
	}
}

func TestProxyStillBlocksAttacks(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("attack reached the backend")
	}))
	defer be.Close()
	_ = Configure(be.URL, 10)
	h := waf.AdaptiveProtect(Home)
	req := httptest.NewRequest("POST", "/login", strings.NewReader("user=admin'--&pass=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0")
	req.RemoteAddr = "203.0.113.10:1234"
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}
