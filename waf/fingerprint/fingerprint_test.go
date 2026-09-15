package fingerprint

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newMW() *Middleware {
	return NewMiddleware(NewTracker(Config{Enabled: true, MaxIPsPerFingerprint: 5, MaxAgeForReuse: time.Hour}))
}

func TestForgedCookieIsNotStored(t *testing.T) {
	mw := newMW()
	h := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	forged := strings.Repeat("ab", 32)
	for i := 0; i < 50; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "203.0.113.1:1"
		r.Header.Set("Accept", "text/html")
		r.AddCookie(&http.Cookie{Name: "waf_fingerprint", Value: forged})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		// unknown hash means start over: the collection page, not a pass-through
		if !strings.Contains(rr.Body.String(), "/fingerprint/collect") {
			t.Fatal("forged cookie was accepted")
		}
	}
	if _, ok := mw.tracker.GetFingerprint(forged); ok {
		t.Fatal("forged hash ended up in the tracker")
	}
	if len(mw.tracker.fingerprints) != 0 {
		t.Fatalf("tracker grew to %d entries from forged cookies", len(mw.tracker.fingerprints))
	}
}

func TestCollectThenCookieAccepted(t *testing.T) {
	mw := newMW()
	body := `{"screen_width":1920,"screen_height":1080,"color_depth":24,"canvas":"abc","webgl":"gpu","fonts":["Arial"],"platform":"Linux"}`
	r := httptest.NewRequest("POST", "/fingerprint/collect", strings.NewReader(body))
	r.RemoteAddr = "203.0.113.1:1"
	rr := httptest.NewRecorder()
	mw.CollectHandler(rr, r)
	if rr.Code != 200 {
		t.Fatalf("collect failed: %d %s", rr.Code, rr.Body.String())
	}
	var hash string
	for _, c := range rr.Result().Cookies() {
		if c.Name == "waf_fingerprint" {
			hash = c.Value
		}
	}
	if !isHashLike(hash) {
		t.Fatalf("bad cookie %q", hash)
	}

	passed := false
	h := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { passed = true }))
	for i := 0; i < 20; i++ {
		r := httptest.NewRequest("GET", "/page", nil)
		r.RemoteAddr = "203.0.113.1:1"
		r.Header.Set("Accept", "text/html")
		r.AddCookie(&http.Cookie{Name: "waf_fingerprint", Value: hash})
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if !passed {
		t.Fatal("known fingerprint cookie not accepted")
	}
	// ipToHash used to append the hash once per request
	if n := len(mw.tracker.ipToHash["203.0.113.1"]); n != 1 {
		t.Fatalf("ipToHash grew to %d entries for one fingerprint", n)
	}
}
