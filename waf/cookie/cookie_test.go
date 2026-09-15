package cookie

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner(RandomKey())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignVerify(t *testing.T) {
	s := newSigner(t)
	v := s.Sign("10.0.0.0/24", time.Minute)
	p, ok := s.Verify(v)
	if !ok || p != "10.0.0.0/24" {
		t.Fatalf("verify: %q %v", p, ok)
	}
	// payload with dots and unicode survives base64
	v = s.Sign("a.b.c|ü", time.Minute)
	if p, ok := s.Verify(v); !ok || p != "a.b.c|ü" {
		t.Fatalf("dotted payload: %q %v", p, ok)
	}
}

func TestTamper(t *testing.T) {
	s := newSigner(t)
	v := s.Sign("x", time.Minute)
	cases := map[string]string{
		"flip sig":     v[:len(v)-1] + "A",
		"flip payload": "Q" + v[1:],
		"no dots":      "abc",
		"empty":        "",
		"one dot":      "a.b",
		"bump exp":     bumpExp(v),
	}
	for name, bad := range cases {
		if _, ok := s.Verify(bad); ok {
			t.Errorf("%s: accepted %q", name, bad)
		}
	}
	// different key, same value
	other := newSigner(t)
	if _, ok := other.Verify(v); ok {
		t.Error("other key accepted")
	}
}

func bumpExp(v string) string {
	parts := strings.Split(v, ".")
	parts[1] = "9999999999"
	return strings.Join(parts, ".")
}

func TestExpired(t *testing.T) {
	s := newSigner(t)
	v := s.Sign("x", -time.Second)
	if _, ok := s.Verify(v); ok {
		t.Fatal("expired token accepted")
	}
}

func TestShortKey(t *testing.T) {
	if _, err := NewSigner([]byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestSetGet(t *testing.T) {
	s := newSigner(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	s.Set(rec, req, "waf_ok", "p", time.Hour)
	c := rec.Result().Cookies()
	if len(c) != 1 || c[0].Name != "waf_ok" || !c[0].HttpOnly || c[0].Secure {
		t.Fatalf("cookie attrs: %+v", c)
	}
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(c[0])
	if p, ok := s.Get(req2, "waf_ok"); !ok || p != "p" {
		t.Fatalf("get: %q %v", p, ok)
	}
	if _, ok := s.Get(req2, "missing"); ok {
		t.Fatal("missing cookie ok")
	}
	// behind a tls-terminating proxy we still mark it Secure
	rec = httptest.NewRecorder()
	req.Header.Set("X-Forwarded-Proto", "https")
	s.Set(rec, req, "waf_ok", "p", time.Hour)
	if !rec.Result().Cookies()[0].Secure {
		t.Fatal("xfp https not secure")
	}
	_ = http.StatusOK
}

func TestIPClass(t *testing.T) {
	cases := map[string]string{
		"203.0.113.77":         "203.0.113.0/24",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"::ffff:10.1.2.3":      "10.1.2.0/24",
		"garbage":              "garbage",
	}
	for in, want := range cases {
		if got := IPClass(in); got != want {
			t.Errorf("IPClass(%q)=%q want %q", in, got, want)
		}
	}
}
