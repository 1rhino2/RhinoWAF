package ddos

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGlobalURLLimitAppliesWithoutPerIPRule(t *testing.T) {
	dir := t.TempDir()
	cfg := `{
  "version": "2.0",
  "last_modified": "2026-07-15T00:00:00Z",
  "banned_ips": [],
  "whitelisted_ips": [],
  "monitored_ips": [],
  "challenged_ips": [],
  "throttled_ips": [],
  "geo_rules": [],
  "asn_rules": [],
  "global_rules": {
    "default_action": "allow",
    "block_empty_user_agent": false,
    "block_suspicious_ua": false,
    "max_url_length": 100,
    "blocked_paths": ["/.env", "/.git/*"],
    "allowed_methods": ["GET", "POST"]
  }
}`
	path := filepath.Join(dir, "ip_rules.json")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InitIPManager(path, false); err != nil {
		t.Fatal(err)
	}
	mgr := GetIPManager()
	if mgr == nil {
		t.Fatal("expected ip manager")
	}

	long := &RequestContext{
		IP:        "203.0.113.50",
		Path:      "/x",
		FullURL:   "http://example.com/x?" + strings.Repeat("a", 200),
		Method:    "GET",
		UserAgent: "Mozilla/5.0",
		Timestamp: time.Now(),
		Headers:   map[string]string{},
		Cookies:   map[string]string{},
	}
	ok, reason := mgr.ValidateRequest(long)
	if ok || reason != "url_too_long" {
		t.Fatalf("expected url_too_long, got ok=%v reason=%q", ok, reason)
	}

	env := &RequestContext{
		IP: "203.0.113.51", Path: "/.env", FullURL: "http://example.com/.env",
		Method: "GET", UserAgent: "Mozilla/5.0", Timestamp: time.Now(),
		Headers: map[string]string{}, Cookies: map[string]string{},
	}
	ok, reason = mgr.ValidateRequest(env)
	if ok || reason != "path_blocked_global" {
		t.Fatalf("expected path_blocked_global, got ok=%v reason=%q", ok, reason)
	}

	trace := &RequestContext{
		IP: "203.0.113.52", Path: "/", FullURL: "http://example.com/",
		Method: "TRACE", UserAgent: "Mozilla/5.0", Timestamp: time.Now(),
		Headers: map[string]string{}, Cookies: map[string]string{},
	}
	ok, reason = mgr.ValidateRequest(trace)
	if ok || reason != "method_not_allowed" {
		t.Fatalf("expected method_not_allowed, got ok=%v reason=%q", ok, reason)
	}
}
