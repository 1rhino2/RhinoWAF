package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileSinkWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engine.log")
	s := NewFileSink(path, 10, 7, 3, false)
	s.Log(Event{Time: time.Now(), IP: "1.2.3.4", Method: "GET", Path: "/x", Action: "block",
		Score: 7, Threshold: 5, Evidence: []Evidence{{RuleID: 942100, Category: "sqli"}}})
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("engine.log not written: %v", err)
	}
	if !strings.Contains(string(b), `"rule":942100`) || !strings.Contains(string(b), `"action":"block"`) {
		t.Fatalf("json line wrong: %s", b)
	}
	// ring keeps it for the explain endpoint
	if r := s.Recent(5); len(r) != 1 || r[0].IP != "1.2.3.4" {
		t.Fatalf("recent: %+v", r)
	}
}

func TestEngineLogEventGoesToSink(t *testing.T) {
	dir := t.TempDir()
	sink := NewFileSink(filepath.Join(dir, "engine.log"), 10, 7, 3, false)
	rs, _ := Loader{}.Load()
	e := New(DefaultConfig(), rs)
	e.SetSink(sink)
	v := inBody(e, "' or 1=1--")
	if !v.Blocked() {
		t.Fatal("expected block")
	}
	e.LogEvent(v, "req1", "9.9.9.9", "example.com", "POST", "/submit")
	if r := sink.Recent(1); len(r) != 1 || r[0].Action != "block" {
		t.Fatalf("logevent did not reach sink: %+v", r)
	}
}
