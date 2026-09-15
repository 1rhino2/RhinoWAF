package autoban

import (
	"testing"
	"time"
)

type memStore struct {
	bans map[string]time.Time
	perm map[string]bool
	del  int
}

func newMem() *memStore { return &memStore{bans: map[string]time.Time{}, perm: map[string]bool{}} }
func (m *memStore) LoadBans() map[string]time.Time {
	out := map[string]time.Time{}
	for k, v := range m.bans {
		out[k] = v
	}
	for k := range m.perm {
		out[k] = time.Time{}
	}
	return out
}
func (m *memStore) SaveBan(ip string, until time.Time, perm bool) {
	if perm {
		m.perm[ip] = true
	} else {
		m.bans[ip] = until
	}
}
func (m *memStore) DeleteBan(ip string) { delete(m.bans, ip); m.del++ }

func cfg() Config {
	return Config{Enabled: true, ViolationLimit: 3, WindowDuration: time.Minute, BanDuration: time.Hour, PermanentAfter: 100}
}

func TestBansAfterLimit(t *testing.T) {
	tr := NewTracker(cfg())
	var banned string
	tr.OnBan(func(ip, reason string, until time.Time) { banned = ip })
	for i := 0; i < 2; i++ {
		tr.RecordViolation("1.2.3.4", "sqli")
	}
	if tr.IsBanned("1.2.3.4") {
		t.Fatal("banned too early")
	}
	tr.RecordViolation("1.2.3.4", "sqli")
	if !tr.IsBanned("1.2.3.4") {
		t.Fatal("should be banned after 3")
	}
	if banned != "1.2.3.4" {
		t.Fatal("onban not fired")
	}
}

func TestPersistRoundTrip(t *testing.T) {
	store := newMem()
	tr := NewTracker(cfg())
	tr.SetPersist(store)
	for i := 0; i < 3; i++ {
		tr.RecordViolation("9.9.9.9", "xss")
	}
	if len(store.bans) != 1 {
		t.Fatalf("ban not persisted: %+v", store.bans)
	}
	// a fresh tracker loading the same store sees the ban
	tr2 := NewTracker(cfg())
	tr2.SetPersist(store)
	if !tr2.IsBanned("9.9.9.9") {
		t.Fatal("ban did not survive into new tracker")
	}
}

func TestExpiredBanNotLoaded(t *testing.T) {
	store := newMem()
	store.bans["old"] = time.Now().Add(-time.Hour)
	tr := NewTracker(cfg())
	tr.SetPersist(store)
	if tr.IsBanned("old") {
		t.Fatal("expired ban loaded")
	}
	if store.del == 0 {
		t.Fatal("expired ban not cleaned from store")
	}
}
