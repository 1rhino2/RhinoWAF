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

func TestVersionBranding(t *testing.T) {
	if Name != "RhinoWAF" {
		t.Fatalf("expected RhinoWAF branding, got %s", Name)
	}
	// stay on the 1.0.x line the project reset to; bump here on a minor/major
	if !strings.HasPrefix(Version, "1.0.") {
		t.Fatalf("expected a 1.0.x version, got %s", Version)
	}
}
