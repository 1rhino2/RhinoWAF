// Package statewire glues the storage layer (waf/state) to the pieces that
// want to persist: the cookie signing key and the auto-ban list. It lives
// apart so waf/state stays a plain key-value store and waf/autoban and
// waf/cookie stay free of the bbolt import.
package statewire

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"time"

	"rhinowaf/waf/cookie"
	"rhinowaf/waf/state"
)

const cookieKeyName = "cookie_secret"

// SignerFromState returns a cookie signer keyed by the persisted secret,
// generating and storing one on first run so passes survive a restart. A
// nil or memory db still yields a working signer (its key just resets on
// restart, which only means clients re-solve one challenge).
func SignerFromState(db *state.DB) *cookie.Signer {
	var key []byte
	if b, err := db.Get(state.BucketMeta, cookieKeyName); err == nil && len(b) >= 16 {
		if dk, derr := base64.StdEncoding.DecodeString(string(b)); derr == nil && len(dk) >= 16 {
			key = dk
		}
	}
	if key == nil {
		key = cookie.RandomKey()
		enc := base64.StdEncoding.EncodeToString(key)
		if err := db.Put(state.BucketMeta, cookieKeyName, []byte(enc)); err != nil {
			log.Printf("state: could not persist cookie key: %v", err)
		}
	}
	s, err := cookie.NewSigner(key)
	if err != nil {
		// RandomKey is always long enough, so this only trips on a corrupt
		// stored key; fall back to a fresh one rather than dying.
		s, _ = cookie.NewSigner(cookie.RandomKey())
	}
	return s
}

// BanStore implements autoban.Persist over the state db.
type BanStore struct{ DB *state.DB }

type banRec struct {
	Until     time.Time `json:"until"`
	Permanent bool      `json:"permanent"`
}

func (b BanStore) LoadBans() map[string]time.Time {
	out := map[string]time.Time{}
	_ = b.DB.ForEach(state.BucketBans, func(ip string, v []byte) bool {
		var r banRec
		if json.Unmarshal(v, &r) == nil {
			if r.Permanent {
				out[ip] = time.Time{}
			} else {
				out[ip] = r.Until
			}
		}
		return true
	})
	return out
}

func (b BanStore) SaveBan(ip string, until time.Time, permanent bool) {
	_ = b.DB.PutJSON(state.BucketBans, ip, banRec{Until: until, Permanent: permanent})
}

func (b BanStore) DeleteBan(ip string) { _ = b.DB.Delete(state.BucketBans, ip) }
