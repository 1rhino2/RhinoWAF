package challenge

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"rhinowaf/waf/cookie"
)

func TestSignedPassSkipsChallenge(t *testing.T) {
	signer, _ := cookie.NewSigner(cookie.RandomKey())
	m := NewMiddleware(NewManager(), Config{Enabled: true, DefaultType: TypeJavaScript, Difficulty: 3, RequireForPaths: []string{"/"}})
	m.SetSigner(signer, time.Hour)

	reached := false
	h := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))

	// no cookie: a required path must be challenged, not passed
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if reached {
		t.Fatal("passed without solving")
	}

	// a valid signed pass for the same ip class goes straight through
	reached = false
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "203.0.113.5:5555"
	req2.AddCookie(&http.Cookie{Name: "waf_ok", Value: signer.Sign(cookie.IPClass("203.0.113.5"), time.Hour)})
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if !reached {
		t.Fatal("valid signed pass did not skip the challenge")
	}

	// a pass minted for a different ip class must not work
	reached = false
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "198.51.100.9:2222"
	req3.AddCookie(&http.Cookie{Name: "waf_ok", Value: signer.Sign(cookie.IPClass("203.0.113.5"), time.Hour)})
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if reached {
		t.Fatal("pass from another ip class was accepted")
	}
}
