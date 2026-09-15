package ddos

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func writeRules(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// the manager is a package singleton, so reuse whatever path it was born with
func testManager(t *testing.T) *IPManager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ip_rules.json")
	writeRules(t, path, `{"version":"2.0","global_rules":{"default_action":"allow"}}`)
	if err := InitIPManager(path, false); err != nil {
		t.Fatal(err)
	}
	return GetIPManager()
}

func TestReloadPicksUpFileChanges(t *testing.T) {
	mgr := testManager(t)
	writeRules(t, mgr.configPath, `{"version":"2.0","banned_ips":[{"ip":"192.0.2.77","type":"ban"}],"global_rules":{"default_action":"allow"}}`)
	if err := mgr.Reload(); err != nil {
		t.Fatal(err)
	}
	if !mgr.IsBanned("192.0.2.77") {
		t.Fatal("ban from reloaded file not applied")
	}

	// broken json keeps the previous rules live
	writeRules(t, mgr.configPath, `{"version":"2.0", "banned_ips": [`)
	if err := mgr.Reload(); err == nil {
		t.Fatal("expected parse error")
	}
	if !mgr.IsBanned("192.0.2.77") {
		t.Fatal("bad reload wiped the old rules")
	}

	writeRules(t, mgr.configPath, `{"version":"2.0","global_rules":{"default_action":"allow"}}`)
	if err := mgr.Reload(); err != nil {
		t.Fatal(err)
	}
	if mgr.IsBanned("192.0.2.77") {
		t.Fatal("unban not applied")
	}
}

// ValidateRequest used to RLock twice; with a writer waiting in between that
// deadlocks. Hammer readers against writers and make sure it finishes.
func TestValidateRequestUnderWriteContention(t *testing.T) {
	mgr := testManager(t)
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 500; j++ {
					mgr.ValidateRequest(&RequestContext{
						IP: "192.0.2.5", Path: "/", FullURL: "/", Method: "GET",
						UserAgent: "Mozilla/5.0", Timestamp: time.Now(),
						Headers: map[string]string{}, Cookies: map[string]string{},
					})
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = mgr.BanIP("192.0.2.99", "test", "t", 0, nil)
				_ = mgr.UnbanIP("192.0.2.99")
			}
		}()
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("ValidateRequest deadlocked against a writer")
	}
}

func TestMinRequestInterval(t *testing.T) {
	mgr := testManager(t)
	writeRules(t, mgr.configPath, `{"version":"2.0","throttled_ips":[{"ip":"192.0.2.8","type":"throttle","min_request_interval":500}],"global_rules":{"default_action":"allow"}}`)
	if err := mgr.Reload(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ctx := func(ts time.Time) *RequestContext {
		return &RequestContext{IP: "192.0.2.8", Path: "/", FullURL: "/", Method: "GET", UserAgent: "x",
			Timestamp: ts, Headers: map[string]string{}, Cookies: map[string]string{}}
	}
	if ok, _ := mgr.ValidateRequest(ctx(now)); !ok {
		t.Fatal("first request should pass")
	}
	if ok, reason := mgr.ValidateRequest(ctx(now.Add(100 * time.Millisecond))); ok || reason != "request_too_fast" {
		t.Fatalf("second request should be too fast, got ok=%v %s", ok, reason)
	}
	if ok, _ := mgr.ValidateRequest(ctx(now.Add(time.Second))); !ok {
		t.Fatal("request after the interval should pass")
	}
}

// same IP from many goroutines used to race on the request slices
func TestAllowL7ConcurrentSameIP(t *testing.T) {
	_ = testManager(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				AllowL7("192.0.2.42")
				AllowL4("192.0.2.42")
				GetIPInfo("192.0.2.42")
			}
		}()
	}
	wg.Wait()
	GetStats()
}

func TestReputationBlockExpires(t *testing.T) {
	_ = testManager(t)
	ip := "192.0.2.43"
	tracker.ResetIP(ip)
	entry := tracker.GetOrCreate(ip)
	entry.mu.Lock()
	entry.Reputation = cfg.ReputationThreshold - 5
	entry.mu.Unlock()
	if !tracker.IsBlocked(ip) {
		t.Fatal("low reputation should block")
	}
	entry.mu.Lock()
	rep := entry.Reputation
	entry.BlockedUntil = 0 // pretend the block window passed
	entry.mu.Unlock()
	if rep <= cfg.ReputationThreshold {
		t.Fatalf("reputation left at %d, would re-block forever", rep)
	}
	if tracker.IsBlocked(ip) {
		t.Fatal("still blocked after the window expired")
	}
}
