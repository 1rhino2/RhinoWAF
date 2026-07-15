package vhost

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestServeHTTPRunsWAFBeforeProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("backend should not be reached for blocked requests")
	}))
	defer backend.Close()

	cfg := VHostConfig{
		Backends: []BackendConfig{
			{Domain: "app.test", Backend: backend.URL, Enabled: true},
		},
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "backends.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	mgr, err := NewVHostManager(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/?q=1+union+select+1", nil)
	req.Host = "app.test"
	req.Header.Set("User-Agent", "Mozilla/5.0 test")
	rec := httptest.NewRecorder()
	mgr.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected vhost path to block attack, got %d", rec.Code)
	}
}

func TestServeHTTPProxiesCleanRequest(t *testing.T) {
	hit := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := VHostConfig{
		Backends: []BackendConfig{
			{Domain: "app.test", Backend: backend.URL, Enabled: true},
		},
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "backends.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	mgr, err := NewVHostManager(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Host = "app.test"
	req.Header.Set("User-Agent", "Mozilla/5.0 test")
	rec := httptest.NewRecorder()
	mgr.ServeHTTP(rec, req)

	if !hit {
		t.Fatal("expected clean request to reach backend")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from backend, got %d", rec.Code)
	}
}
