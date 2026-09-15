package waf

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalhostOnly(t *testing.T) {
	h := LocalhostOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	cases := []struct {
		remote, xff string
		want        int
	}{
		{"127.0.0.1:1", "", 200},
		{"[::1]:1", "", 200},
		{"127.0.0.2:1", "", 200},
		{"203.0.113.1:1", "", 403},
		{"203.0.113.1:1", "127.0.0.1", 403}, // spoof from outside
		{"127.0.0.1:1", "203.0.113.1", 403}, // local proxy forwarding for a remote
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/metrics", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if rr.Code != c.want {
			t.Errorf("remote=%s xff=%q: got %d want %d", c.remote, c.xff, rr.Code, c.want)
		}
	}
}
