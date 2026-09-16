package reload

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// a *.rules change inside a watched dir calls the engine reload hook, both
// from the watcher path and from ReloadAll; a random file elsewhere does not
func TestRulesDirTriggersReload(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	m, err := NewManager(Config{
		RulesDirs:    []string{dir},
		RulesReload:  func() error { calls++; return nil },
		DebounceTime: time.Millisecond,
		WatchEnabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Stop() }()

	m.handleFileChange(filepath.Join(dir, "10-tune.rules"))
	if calls != 1 {
		t.Fatalf("rules change not reloaded: %d calls", calls)
	}
	m.handleFileChange(filepath.Join(t.TempDir(), "10-tune.rules")) // other dir
	m.handleFileChange(filepath.Join(dir, "notes.md"))              // wrong suffix
	if calls != 1 {
		t.Fatalf("unrelated changes reloaded rules: %d calls", calls)
	}
	time.Sleep(2 * time.Millisecond)
	if err := m.ReloadAll(); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("ReloadAll skipped rules: %d calls", calls)
	}
}

// with the watcher on, an actual write lands in the hook
func TestRulesDirWatched(t *testing.T) {
	dir := t.TempDir()
	got := make(chan struct{}, 4)
	m, err := NewManager(Config{
		RulesDirs:    []string{dir},
		RulesReload:  func() error { got <- struct{}{}; return nil },
		DebounceTime: time.Millisecond,
		WatchEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Stop() }()
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(dir, "10-tune.rules"), []byte("disable 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("watcher did not fire for a rules file write")
	}
}
