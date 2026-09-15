package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rhinowaf/waf/autoban"
	"rhinowaf/waf/bodylimits"
	"rhinowaf/waf/engine"
	"rhinowaf/waf/exemptions"
)

func TestExemptSkipsEngine(t *testing.T) {
	installEngine(t)
	h, _ := exemptions.NewHandler(exemptions.Config{Enabled: true, UserAgents: []string{"health-check"}})
	SetExemptions(h)
	t.Cleanup(func() { SetExemptions(nil) })

	// an sqli that would normally block, but from an exempt UA
	req := httptest.NewRequest("GET", "/?q="+enc("' or 1=1--"), nil)
	req.Header.Set("User-Agent", "health-check/1.0")
	rec := httptest.NewRecorder()
	if !ProtectRequest(rec, req) {
		t.Fatal("exempt client was blocked")
	}
	// same payload from a normal UA still blocks
	req2 := httptest.NewRequest("GET", "/?q="+enc("' or 1=1--"), nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	rec2 := httptest.NewRecorder()
	if ProtectRequest(rec2, req2) {
		t.Fatal("non-exempt attack not blocked")
	}
}

func TestBodyLimit413(t *testing.T) {
	SetBodyLimiter(bodylimits.NewLimiter(bodylimits.Config{Enabled: true, GlobalLimit: 100}))
	t.Cleanup(func() { SetBodyLimiter(nil) })

	big := strings.NewReader(strings.Repeat("x", 500))
	req := httptest.NewRequest("POST", "/upload", big)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.ContentLength = 500
	rec := httptest.NewRecorder()
	if ProtectRequest(rec, req) {
		t.Fatal("oversized body not rejected")
	}
	if rec.Code != 413 {
		t.Fatalf("expected 413, got %d", rec.Code)
	}
}

func TestHoneypotBans(t *testing.T) {
	tr := autoban.NewTracker(autoban.Config{Enabled: true, ViolationLimit: 3, WindowDuration: time.Minute, BanDuration: time.Hour, PermanentAfter: 1000})
	SetAutoBan(tr)
	SetHoneypot([]string{"/.env"}, time.Hour)
	t.Cleanup(func() { SetAutoBan(nil); SetHoneypot(nil, 0) })

	req := httptest.NewRequest("GET", "/.env", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.RemoteAddr = "203.0.113.50:1234"
	rec := httptest.NewRecorder()
	if ProtectRequest(rec, req) {
		t.Fatal("honeypot path not blocked")
	}
	if !tr.IsBanned("203.0.113.50") {
		t.Fatal("honeypot hit did not ban the client")
	}
	_ = engine.Active
	_ = http.StatusOK
}
