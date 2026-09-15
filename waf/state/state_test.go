package state

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func TestRoundTripAndReopen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.db")
	db := Open(p)
	if !db.Persistent() {
		t.Fatal("expected bbolt mode")
	}
	if err := db.PutJSON(BucketBans, "1.2.3.4", map[string]string{"why": "test"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db = Open(p)
	defer db.Close()
	var got map[string]string
	if err := db.GetJSON(BucketBans, "1.2.3.4", &got); err != nil || got["why"] != "test" {
		t.Fatalf("reopen lost data: %v %v", got, err)
	}
	if _, err := db.Get(BucketBans, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := db.Delete(BucketBans, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if db.Count(BucketBans) != 0 {
		t.Fatal("delete did not stick")
	}
}

func TestMemoryFallback(t *testing.T) {
	// a directory path cannot be opened as a file, so we should fall back
	db := Open(t.TempDir())
	if db.Persistent() {
		t.Fatal("expected memory mode")
	}
	_ = db.Put("b", "k", []byte("v"))
	v, err := db.Get("b", "k")
	if err != nil || string(v) != "v" {
		t.Fatalf("mem get: %q %v", v, err)
	}
	// value is a copy, mutating it must not leak into the store
	v[0] = 'x'
	v2, _ := db.Get("b", "k")
	if string(v2) != "v" {
		t.Fatal("stored value aliased")
	}
	n := 0
	_ = db.ForEach("b", func(k string, _ []byte) bool { n++; return true })
	if n != 1 {
		t.Fatalf("foreach saw %d", n)
	}
}

func TestNilDBIsSafe(t *testing.T) {
	var db *DB
	if _, err := db.Get("a", "b"); !errors.Is(err, ErrNotFound) {
		t.Fatal("nil get")
	}
	if err := db.Put("a", "b", nil); err != nil {
		t.Fatal("nil put")
	}
	if err := db.Close(); err != nil {
		t.Fatal("nil close")
	}
}

func TestConcurrent(t *testing.T) {
	for _, path := range []string{"", filepath.Join(t.TempDir(), "c.db")} {
		db := Open(path)
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				k := string(rune('a' + i%26))
				for j := 0; j < 50; j++ {
					_ = db.Put("x", k, []byte{byte(j)})
					_, _ = db.Get("x", k)
					_ = db.ForEach("x", func(string, []byte) bool { return true })
				}
			}(i)
		}
		wg.Wait()
		db.Close()
	}
}
