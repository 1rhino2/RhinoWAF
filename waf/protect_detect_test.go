package waf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"rhinowaf/waf/engine"
)

// detect mode: request goes through, and the response header names the
// rules that would have blocked it so staging can be watched from a browser
func TestDetectModeSetsHeader(t *testing.T) {
	rs, err := engine.Loader{}.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg := engine.DefaultConfig()
	cfg.Mode = "detect"
	engine.SetDefault(engine.New(cfg, rs))
	t.Cleanup(func() { engine.SetDefault(nil) })

	reached := false
	mw := ProtectMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	req := httptest.NewRequest("GET", "/search?q="+enc("' or 1=1--"), nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if !reached || rec.Code != 200 {
		t.Fatalf("detect mode blocked: reached=%v code=%d", reached, rec.Code)
	}
	if h := rec.Header().Get("X-WAF-Detect"); h == "" || !contains(h, "942100") {
		t.Fatalf("X-WAF-Detect missing or wrong: %q", h)
	}

	// clean request carries no header
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/search?q=shoes", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	mw.ServeHTTP(rec2, req2)
	if rec2.Header().Get("X-WAF-Detect") != "" {
		t.Fatal("header set on a clean request")
	}

	// explain_on_block none hides it
	cfg.ExplainOnBlock = "none"
	engine.SetDefault(engine.New(cfg, rs))
	rec3 := httptest.NewRecorder()
	mw.ServeHTTP(rec3, req)
	if rec3.Header().Get("X-WAF-Detect") != "" {
		t.Fatal("header set with explain_on_block=none")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
