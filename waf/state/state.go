// Package state is the one place RhinoWAF keeps things across restarts:
// auto-bans, violation counters, reputation lookups, the cookie signing key.
// It is a single bbolt file next to the logs. If the file cannot be opened
// (read-only fs, locked by another instance, whatever) we log once and run
// in memory, because a WAF that refuses to start over a db file is worse
// than one that forgets its bans.
package state

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// bucket names, kept here so callers don't typo them
const (
	BucketBans        = "bans"
	BucketReputation  = "reputation"
	BucketViolations  = "violations"
	BucketFingerprint = "fingerprints"
	BucketMeta        = "meta"
)

var ErrNotFound = errors.New("state: not found")

// DB wraps bbolt, or a map when bbolt is unavailable. Safe for concurrent use.
type DB struct {
	db   *bolt.DB
	path string

	mu  sync.RWMutex
	mem map[string]map[string][]byte // bucket -> key -> value, fallback only
}

// Open opens or creates the db file. Never returns an error for the file
// itself, see package doc. An empty path means memory only.
func Open(path string) *DB {
	d := &DB{path: path}
	if path == "" {
		d.mem = map[string]map[string][]byte{}
		return d
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		log.Printf("[STATE] cannot create %s: %v, running in memory", filepath.Dir(path), err)
		d.mem = map[string]map[string][]byte{}
		return d
	}
	// timeout so a second instance on the same file fails fast instead of hanging
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		log.Printf("[STATE] cannot open %s: %v, running in memory", path, err)
		d.mem = map[string]map[string][]byte{}
		return d
	}
	d.db = db
	return d
}

// Persistent reports whether writes survive a restart.
func (d *DB) Persistent() bool { return d != nil && d.db != nil }

// Path is the file in use, empty in memory mode.
func (d *DB) Path() string {
	if d == nil || d.db == nil {
		return ""
	}
	return d.path
}

func (d *DB) Close() error {
	if d == nil || d.db == nil {
		return nil
	}
	return d.db.Close()
}

// Get returns a copy of the value. ErrNotFound when the key or bucket is missing.
func (d *DB) Get(bucket, key string) ([]byte, error) {
	if d == nil {
		return nil, ErrNotFound
	}
	if d.db == nil {
		d.mu.RLock()
		defer d.mu.RUnlock()
		b := d.mem[bucket]
		if b == nil {
			return nil, ErrNotFound
		}
		v, ok := b[key]
		if !ok {
			return nil, ErrNotFound
		}
		return append([]byte(nil), v...), nil
	}
	var out []byte
	err := d.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return ErrNotFound
		}
		v := b.Get([]byte(key))
		if v == nil {
			return ErrNotFound
		}
		out = append([]byte(nil), v...)
		return nil
	})
	return out, err
}

func (d *DB) Put(bucket, key string, val []byte) error {
	if d == nil {
		return nil
	}
	if d.db == nil {
		d.mu.Lock()
		defer d.mu.Unlock()
		b := d.mem[bucket]
		if b == nil {
			b = map[string][]byte{}
			d.mem[bucket] = b
		}
		b[key] = append([]byte(nil), val...)
		return nil
	}
	return d.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		return b.Put([]byte(key), val)
	})
}

func (d *DB) Delete(bucket, key string) error {
	if d == nil {
		return nil
	}
	if d.db == nil {
		d.mu.Lock()
		defer d.mu.Unlock()
		if b := d.mem[bucket]; b != nil {
			delete(b, key)
		}
		return nil
	}
	return d.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(key))
	})
}

// ForEach walks a bucket. fn gets copies, and returning false stops the walk.
// Deleting inside fn is fine, the walk happens over a snapshot.
func (d *DB) ForEach(bucket string, fn func(key string, val []byte) bool) error {
	if d == nil {
		return nil
	}
	type kv struct {
		k string
		v []byte
	}
	var items []kv
	if d.db == nil {
		d.mu.RLock()
		for k, v := range d.mem[bucket] {
			items = append(items, kv{k, append([]byte(nil), v...)})
		}
		d.mu.RUnlock()
	} else {
		err := d.db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(bucket))
			if b == nil {
				return nil
			}
			return b.ForEach(func(k, v []byte) error {
				items = append(items, kv{string(k), append([]byte(nil), v...)})
				return nil
			})
		})
		if err != nil {
			return err
		}
	}
	for _, it := range items {
		if !fn(it.k, it.v) {
			break
		}
	}
	return nil
}

// PutJSON / GetJSON are what most callers want, the raw form is for blobs.
func (d *DB) PutJSON(bucket, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return d.Put(bucket, key, b)
}

func (d *DB) GetJSON(bucket, key string, v any) error {
	b, err := d.Get(bucket, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Count is for stats endpoints, not hot paths.
func (d *DB) Count(bucket string) int {
	n := 0
	_ = d.ForEach(bucket, func(string, []byte) bool { n++; return true })
	return n
}
