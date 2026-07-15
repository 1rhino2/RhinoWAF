package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProtectRequestBlocksMaliciousQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?id=1+union+select+null", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 test")
	rec := httptest.NewRecorder()

	if ProtectRequest(rec, req) {
		t.Fatal("expected malicious query to be blocked")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestProtectRequestAllowsCleanGET(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/about", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 test")
	rec := httptest.NewRecorder()

	if !ProtectRequest(rec, req) {
		t.Fatal("expected clean request to pass")
	}
}

func TestProtectRequestBlocksSmugglingHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader("x"))
	req.Header.Set("User-Agent", "Mozilla/5.0 test")
	req.Header.Add("Content-Length", "4")
	req.Header.Add("Content-Length", "8")
	rec := httptest.NewRecorder()

	if ProtectRequest(rec, req) {
		t.Fatal("expected duplicate Content-Length to be blocked")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestVersionIsOnePointZero(t *testing.T) {
	if Version != "1.0.0" {
		t.Fatalf("expected 1.0.0 branding, got %s", Version)
	}
}
