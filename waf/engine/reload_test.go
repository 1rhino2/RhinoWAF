package engine

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestReloadKeepsOldOnError(t *testing.T) {
	e := testEngine(t)
	before := e.Ruleset().hash
	// a bad rules dir (nonexistent) must not swap
	err := e.Reload(Loader{RulesDir: "/does/not/exist"})
	if err == nil {
		t.Fatal("expected load error")
	}
	if e.Ruleset().hash != before {
		t.Fatal("ruleset swapped despite load error")
	}
}

func TestConcurrentInspectAndReload(t *testing.T) {
	e := testEngine(t)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	// reloader
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = e.Reload(Loader{})
		}
	}()
	// hammer inspect from many goroutines
	payloads := []string{"' or 1=1--", "<script>alert(1)</script>", "normal search text", "../../etc/passwd"}
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				p := payloads[i%len(payloads)]
				r := httptest.NewRequest("POST", "/x", strings.NewReader("data="+urlEnc(p)))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				e.Inspect(r)
			}
		}(g)
	}
	wg.Wait()
	close(stop)
}

func TestDetectModeNeverBlocks(t *testing.T) {
	rs, _ := Loader{}.Load()
	cfg := DefaultConfig()
	cfg.Mode = "detect"
	e := New(cfg, rs)
	v := inBody(e, "' or 1=1--")
	if v.Blocked() {
		t.Fatal("detect mode blocked")
	}
	if v.Action != ActBlock || v.Effective != ActAllow {
		t.Fatalf("detect verdict: action=%v effective=%v", v.Action, v.Effective)
	}
	if len(v.Evidence) == 0 {
		t.Fatal("detect mode kept no evidence")
	}
}
