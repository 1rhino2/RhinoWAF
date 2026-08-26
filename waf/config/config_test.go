package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
	if cfg.Server.Listen != ":8080" {
		t.Errorf("expected default listen :8080, got %q", cfg.Server.Listen)
	}
	if !cfg.Challenge.Enabled {
		t.Errorf("expected challenge enabled by default")
	}
}

func TestLoadOverlaysPartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "features.json")
	// only override listen and difficulty; everything else must keep defaults
	body := `{"server":{"listen":":9443"},"challenge_system":{"pow_difficulty":6}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Listen != ":9443" {
		t.Errorf("listen not overridden, got %q", cfg.Server.Listen)
	}
	if cfg.Challenge.PowDifficulty != 6 {
		t.Errorf("difficulty not overridden, got %d", cfg.Challenge.PowDifficulty)
	}
	// untouched section keeps its default
	if cfg.Backend.ProxyURL != "http://localhost:9000" {
		t.Errorf("backend default lost, got %q", cfg.Backend.ProxyURL)
	}
}

func TestLoadStripsBOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "features.json")
	body := append([]byte("\xef\xbb\xbf"), []byte(`{"server":{"listen":":7000"}}`)...)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("BOM should be tolerated, got %v", err)
	}
	if cfg.Server.Listen != ":7000" {
		t.Errorf("got %q", cfg.Server.Listen)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	cases := map[string]string{
		"empty listen":     `{"server":{"listen":""}}`,
		"bad challenge":    `{"challenge_system":{"default_type":"nope"}}`,
		"difficulty range": `{"challenge_system":{"pow_difficulty":99}}`,
		"empty backend":    `{"backend":{"proxy_url":""}}`,
		"unknown field":    `{"totally_made_up":true}`,
		"malformed json":   `{"server":`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "features.json")
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}
