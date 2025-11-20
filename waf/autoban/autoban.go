package autoban

import (
	"sync"
	"time"
)

type Violation struct {
	IP        string
	Reason    string
	Timestamp time.Time
}

type Config struct {
	Enabled        bool
	ViolationLimit int
	WindowDuration time.Duration
	BanDuration    time.Duration
	PermanentAfter int
}

type Tracker struct {
	config     Config
	violations map[string][]time.Time
	banned     map[string]time.Time
	permanent  map[string]bool
	mu         sync.RWMutex
}

func NewTracker(config Config) *Tracker {
	if config.ViolationLimit == 0 {
		config.ViolationLimit = 5
	}
	if config.WindowDuration == 0 {
		config.WindowDuration = 5 * time.Minute
	}
	if config.BanDuration == 0 {
		config.BanDuration = 30 * time.Minute
	}
	if config.PermanentAfter == 0 {
		config.PermanentAfter = 3
	}

	t := &Tracker{
		config:     config,
		violations: make(map[string][]time.Time),
		banned:     make(map[string]time.Time),
		permanent:  make(map[string]bool),
	}

	go t.cleanupLoop()
	return t
}

func (t *Tracker) RecordViolation(ip string) {
	if !t.config.Enabled {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	t.violations[ip] = append(t.violations[ip], now)

	recent := t.countRecentViolations(ip, now)
	if recent >= t.config.ViolationLimit {
		banCount := len(t.banned)
		if banCount >= t.config.PermanentAfter {
			t.permanent[ip] = true
		} else {
			t.banned[ip] = now.Add(t.config.BanDuration)
		}
	}
}

func (t *Tracker) IsBanned(ip string) bool {
	if !t.config.Enabled {
		return false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.permanent[ip] {
		return true
	}

	if expiry, exists := t.banned[ip]; exists {
		return time.Now().Before(expiry)
	}

	return false
}

func (t *Tracker) countRecentViolations(ip string, now time.Time) int {
	cutoff := now.Add(-t.config.WindowDuration)
	count := 0

	for _, ts := range t.violations[ip] {
		if ts.After(cutoff) {
			count++
		}
	}

	return count
}

func (t *Tracker) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		t.cleanup()
	}
}

func (t *Tracker) cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-t.config.WindowDuration * 2)

	for ip, timestamps := range t.violations {
		filtered := make([]time.Time, 0)
		for _, ts := range timestamps {
			if ts.After(cutoff) {
				filtered = append(filtered, ts)
			}
		}
		if len(filtered) > 0 {
			t.violations[ip] = filtered
		} else {
			delete(t.violations, ip)
		}
	}

	for ip, expiry := range t.banned {
		if now.After(expiry) && !t.permanent[ip] {
			delete(t.banned, ip)
		}
	}
}
