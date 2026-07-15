package sanitize

import (
	"net/http/httptest"
	"testing"
)

func TestNoSQLQueryKeyBlocked(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	r := httptest.NewRequest("GET", "/?user%5B%24gt%5D=", nil)
	r.Header.Set("User-Agent", ua)
	if !IsMalicious(r) {
		t.Fatal("nosql operator in query key should be blocked")
	}
}

func TestChromeUserAgentNotMalicious(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	r := httptest.NewRequest("GET", "/about", nil)
	r.Header.Set("User-Agent", ua)
	if IsMalicious(r) {
		t.Fatal("real Chrome UA should not be flagged as malicious input")
	}
}

func TestWeaponizedUserAgentStillBlocked(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "<script>alert(1)</script>")
	if !IsMalicious(r) {
		t.Fatal("XSS in User-Agent should still be blocked")
	}
}

func TestSQLiStillBlockedInQuery(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	r := httptest.NewRequest("GET", "/?id=1+union+select+null", nil)
	r.Header.Set("User-Agent", ua)
	if !IsMalicious(r) {
		t.Fatal("union select in query should still be blocked")
	}
}
