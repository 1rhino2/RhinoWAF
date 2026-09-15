package statewire

import (
	"path/filepath"
	"testing"
	"time"

	"rhinowaf/waf/state"
)

func TestSignerPersistsKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.db")
	db := state.Open(p)
	s1 := SignerFromState(db)
	tok := s1.Sign("10.0.0.0/24", time.Hour)
	db.Close()

	// reopen: the same key must verify a token signed before the restart
	db2 := state.Open(p)
	defer db2.Close()
	s2 := SignerFromState(db2)
	if _, ok := s2.Verify(tok); !ok {
		t.Fatal("cookie key did not survive restart")
	}
}

func TestBanStoreRoundTrip(t *testing.T) {
	db := state.Open(filepath.Join(t.TempDir(), "b.db"))
	defer db.Close()
	bs := BanStore{DB: db}
	until := time.Now().Add(time.Hour).Round(time.Second)
	bs.SaveBan("1.2.3.4", until, false)
	bs.SaveBan("perm", time.Time{}, true)

	got := bs.LoadBans()
	if !got["1.2.3.4"].Equal(until) {
		t.Fatalf("temp ban: %v want %v", got["1.2.3.4"], until)
	}
	if v, ok := got["perm"]; !ok || !v.IsZero() {
		t.Fatalf("perm ban: %v %v", v, ok)
	}
	bs.DeleteBan("1.2.3.4")
	if _, ok := bs.LoadBans()["1.2.3.4"]; ok {
		t.Fatal("delete failed")
	}
}
