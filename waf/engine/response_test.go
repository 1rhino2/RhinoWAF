package engine

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
)

type memSink struct{ events []Event }

func (m *memSink) Log(e Event) { m.events = append(m.events, e) }

// backend that answers whatever the test tells it to
func proxyFor(t *testing.T, e *Engine, status int, ctype, body string, gz bool) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ctype)
		if gz {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(status)
			zw := gzip.NewWriter(w)
			_, _ = zw.Write([]byte(body))
			_ = zw.Close()
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(backend.Close)
	u, _ := url.Parse(backend.URL)
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.ModifyResponse = e.ModifyResponse
	front := httptest.NewServer(rp)
	t.Cleanup(front.Close)
	return front
}

const javaTrace = "HTTP 500\njava.lang.NullPointerException: boom\n\tat com.example.Foo.bar(Foo.java:42)\n"

func TestResponseDetectLogsButPasses(t *testing.T) {
	rs, _ := Loader{}.Load()
	cfg := DefaultConfig() // response.mode = detect
	e := New(cfg, rs)
	sink := &memSink{}
	e.SetSink(sink)
	front := proxyFor(t, e, 500, "text/plain", javaTrace, false)

	resp, err := http.Get(front.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 500 || !strings.Contains(string(b), "NullPointerException") {
		t.Fatalf("detect mode altered the response: %d %q", resp.StatusCode, b)
	}
	if len(sink.events) != 1 || sink.events[0].Action != "detect" || sink.events[0].Phase != "response-body" {
		t.Fatalf("expected one detect event, got %+v", sink.events)
	}
}

func TestResponseBlockReplacesBody(t *testing.T) {
	rs, _ := Loader{}.Load()
	cfg := DefaultConfig()
	cfg.Response.Mode = "block"
	e := New(cfg, rs)
	front := proxyFor(t, e, 500, "text/html", javaTrace, false)

	resp, err := http.Get(front.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 403 {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
	if strings.Contains(string(b), "NullPointerException") {
		t.Fatal("leak still in body")
	}
	if cl := resp.Header.Get("Content-Length"); cl != strconv.Itoa(len(b)) {
		t.Fatalf("content-length %s vs body %d", cl, len(b))
	}
	if resp.Header.Get("Content-Encoding") != "" {
		t.Fatal("content-encoding not cleared")
	}
	if !strings.Contains(string(b), "950140") {
		t.Fatalf("block page lacks the rule id: %s", b)
	}
}

func TestResponseGzipIsDecompressed(t *testing.T) {
	rs, _ := Loader{}.Load()
	cfg := DefaultConfig()
	cfg.Response.Mode = "block"
	e := New(cfg, rs)
	front := proxyFor(t, e, 500, "text/plain", javaTrace, true)
	resp, err := http.Get(front.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("gzip leak not caught: %d", resp.StatusCode)
	}
}

func TestResponse200NotInspectedIn5xxMode(t *testing.T) {
	rs, _ := Loader{}.Load()
	cfg := DefaultConfig()
	cfg.Response.Mode = "block"
	e := New(cfg, rs)
	front := proxyFor(t, e, 200, "text/plain", javaTrace, false)
	resp, err := http.Get(front.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("200 was inspected in 5xx mode: %d", resp.StatusCode)
	}
}

func TestResponseCleanPassesUntouched(t *testing.T) {
	rs, _ := Loader{}.Load()
	cfg := DefaultConfig()
	cfg.Response.Mode = "block"
	cfg.Response.InspectStatus = "all"
	e := New(cfg, rs)
	body := strings.Repeat("all good here. ", 2000) // bigger than max_bytes
	front := proxyFor(t, e, 200, "text/html", body, false)
	resp, err := http.Get(front.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !bytes.Equal(b, []byte(body)) {
		t.Fatalf("clean body altered: %d len=%d want %d", resp.StatusCode, len(b), len(body))
	}
}

func TestResponseEventStreamSkipped(t *testing.T) {
	rs, _ := Loader{}.Load()
	cfg := DefaultConfig()
	cfg.Response.Mode = "block"
	cfg.Response.InspectStatus = "all"
	e := New(cfg, rs)
	front := proxyFor(t, e, 200, "text/event-stream", "data: "+javaTrace, false)
	resp, err := http.Get(front.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("event stream was inspected")
	}
}

func TestSiteOverrides(t *testing.T) {
	rs, _ := Loader{}.Load()
	e := New(DefaultConfig(), rs)
	e.SetSites(map[string]*SiteOverride{
		"detect.example.com": {Mode: "detect"},
		"loose.example.com":  {DisabledRules: []int{942100, 942150}},
		"*.wild.example.com": {Threshold: 50},
		"paths.example.com": {Paths: []PathOverride{
			{Prefix: "/api/", Mode: "detect"},
		}},
	})
	sqli := "' or 1=1--"
	try := func(host, path string) *Verdict {
		r := httptest.NewRequest("GET", path+"?q="+urlEnc(sqli), nil)
		r.Host = host
		return e.Inspect(r)
	}
	if try("other.example.com", "/").Blocked() != true {
		t.Fatal("baseline should block")
	}
	if v := try("detect.example.com", "/"); v.Blocked() || v.Action != ActBlock {
		t.Fatalf("site detect mode: blocked=%v action=%v", v.Blocked(), v.Action)
	}
	if try("loose.example.com", "/").Blocked() {
		t.Fatal("disabled rules still blocked")
	}
	if try("a.wild.example.com", "/").Blocked() {
		t.Fatal("wildcard threshold not applied")
	}
	if try("paths.example.com", "/api/x").Blocked() {
		t.Fatal("site path override not applied")
	}
	if !try("paths.example.com", "/web/x").Blocked() {
		t.Fatal("site path override leaked to other paths")
	}
	// ipv6 literal host with port still resolves the site
	e.SetSites(map[string]*SiteOverride{"::1": {Mode: "detect"}})
	r := httptest.NewRequest("GET", "/?q="+urlEnc(sqli), nil)
	r.Host = "[::1]:8080"
	if e.Inspect(r).Blocked() {
		t.Fatal("ipv6 host not matched")
	}
}

func TestRulesReloadFromExtraDir(t *testing.T) {
	dir := t.TempDir()
	l := Loader{ExtraDir: dir}
	rs, err := l.Load()
	if err != nil {
		t.Fatal(err)
	}
	e := New(DefaultConfig(), rs)
	e.SetLoader(l)
	if !inQuery(e, "' or 1=1--").Blocked() {
		t.Fatal("baseline should block")
	}
	// operator disables the sqli rules in rules.d, reload picks it up
	if err := os.WriteFile(dir+"/10-tune.rules", []byte("disable 942100\ndisable 942150\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.ReloadRules(); err != nil {
		t.Fatal(err)
	}
	if inQuery(e, "' or 1=1--").Blocked() {
		t.Fatal("reload did not apply the disable")
	}
	// a broken file keeps the last good set
	before := e.Ruleset().Hash()
	_ = os.WriteFile(dir+"/20-bad.rules", []byte("rule x \"broken\" {\n"), 0o644)
	if err := e.ReloadRules(); err == nil {
		t.Fatal("broken file should error")
	}
	if e.Ruleset().Hash() != before {
		t.Fatal("broken reload swapped the ruleset")
	}
	if inQuery(e, "' or 1=1--").Blocked() {
		t.Fatal("state changed after failed reload")
	}
	if got := e.RulesDirs(); len(got) != 1 || got[0] != dir {
		t.Fatalf("RulesDirs: %v", got)
	}
}
