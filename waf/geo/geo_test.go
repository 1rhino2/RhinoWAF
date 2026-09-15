package geo

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// Lookup used to write the cache under the read lock; run with -race
func TestLookupConcurrent(t *testing.T) {
	if err := LoadGeoDatabase(filepath.Join(t.TempDir(), "geoip.json")); err != nil {
		t.Fatal(err)
	}
	if err := AddRange("203.0.113.0/24", "XT", "Test"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 300; j++ {
				ip := fmt.Sprintf("203.0.113.%d", (i*37+j)%256)
				if GetCountryCode(ip) != "XT" {
					t.Errorf("wrong country for %s", ip)
				}
				GetCountryCode(fmt.Sprintf("198.51.100.%d", j%256))
			}
		}(i)
	}
	wg.Wait()
}
