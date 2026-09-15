package security

import (
	"net/http/httptest"
	"testing"
)

func TestGetRealIPIgnoresForwardedFromUntrusted(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:4444"
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.Header.Set("X-Real-IP", "10.0.0.2")
	r.Header.Set("CF-Connecting-IP", "10.0.0.3")
	if got := GetRealIP(r); got != "203.0.113.9" {
		t.Fatalf("spoofed header honored: %s", got)
	}
}

func TestGetRealIPHonorsTrustedProxy(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:4444"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	if got := GetRealIP(r); got != "203.0.113.9" {
		t.Fatalf("got %s", got)
	}
	r.Header.Del("X-Forwarded-For")
	r.Header.Set("CF-Connecting-IP", "198.51.100.7")
	if got := GetRealIP(r); got != "198.51.100.7" {
		t.Fatalf("cf header from trusted proxy not used: %s", got)
	}
	r.Header.Set("CF-Connecting-IP", "not an ip")
	if got := GetRealIP(r); got != "127.0.0.1" {
		t.Fatalf("garbage header should fall back: %s", got)
	}
}

func TestSetTrustedProxies(t *testing.T) {
	defer func() { currentConfig = defaultConfig }()
	if err := SetTrustedProxies([]string{"198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := GetRealIP(r); got != "127.0.0.1" {
		t.Fatalf("loopback should no longer be trusted: %s", got)
	}
	r.RemoteAddr = "198.51.100.4:1"
	if got := GetRealIP(r); got != "203.0.113.9" {
		t.Fatalf("configured proxy not trusted: %s", got)
	}
	if err := SetTrustedProxies([]string{"nope"}); err == nil {
		t.Fatal("bad cidr accepted")
	}
}
