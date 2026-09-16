package vhost

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"rhinowaf/waf/engine"
)

// the engine block in backends.json reaches the engine on load and on reload
func TestEngineBlockReachesEngine(t *testing.T) {
	rs, err := engine.Loader{}.Load()
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(engine.DefaultConfig(), rs)
	engine.SetDefault(eng)
	t.Cleanup(func() { engine.SetDefault(nil) })

	dir := t.TempDir()
	cfg := filepath.Join(dir, "backends.json")
	write := func(mode string) {
		body := `{"backends":[{"domain":"blog.example.com","backend":"http://127.0.0.1:1","enabled":true,"engine":{"mode":"` + mode + `"}}]}`
		if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("detect")
	m, err := NewVHostManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	attack := func() bool {
		r := httptest.NewRequest("GET", "/?q=%27+or+1%3D1--", nil)
		r.Host = "blog.example.com"
		return eng.Inspect(r).Blocked()
	}
	if attack() {
		t.Fatal("site detect mode from backends.json not applied")
	}
	write("block")
	if err := m.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if !attack() {
		t.Fatal("reload did not update the site override")
	}
	// ipv6 literal host resolves to a proxy instead of "[" (old split bug)
	if m.GetProxy("[::1]:8080") != nil {
		t.Fatal("unknown ipv6 host should fall through to nil without a default backend")
	}
	m2, _ := NewVHostManager(cfg)
	m2.config.DefaultBackend = "http://127.0.0.1:2"
	_ = m2.initProxies()
	if m2.GetProxy("[::1]:8080") == nil {
		t.Fatal("ipv6 host did not reach the default proxy")
	}
}
