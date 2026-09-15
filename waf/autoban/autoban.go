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

// Persist lets the tracker keep bans across restarts without importing the
// storage layer. main wires an implementation over the state db.
type Persist interface {
	LoadBans() map[string]time.Time
	SaveBan(ip string, until time.Time, permanent bool)
	DeleteBan(ip string)
}

type Tracker struct {
	config     Config
	violations map[string][]time.Time
	banned     map[string]time.Time
	permanent  map[string]bool
	store      Persist
	onBan      func(ip, reason string, until time.Time)
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

// SetPersist attaches a store and loads any bans it already holds, so a
// restart does not forget who was banned. Call right after NewTracker.
func (t *Tracker) SetPersist(p Persist) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.store = p
	if p == nil {
		return
	}
	now := time.Now()
	for ip, until := range p.LoadBans() {
		if until.IsZero() { // zero means permanent
			t.permanent[ip] = true
		} else if until.After(now) {
			t.banned[ip] = until
		} else {
			p.DeleteBan(ip)
		}
	}
}

// OnBan registers a callback fired when an IP is auto-banned (main uses it
// to push the ban into the IP manager and alert webhooks).
func (t *Tracker) OnBan(fn func(ip, reason string, until time.Time)) { t.onBan = fn }

// RecordViolation notes a violation and bans the IP once it crosses the
// limit inside the window. reason is carried to the ban callback and log.
func (t *Tracker) RecordViolation(ip, reason string) {
	if !t.config.Enabled {
		return
	}
	t.mu.Lock()
	now := time.Now()
	t.violations[ip] = append(t.violations[ip], now)
	var banned bool
	var until time.Time
	var perm bool
	if t.countRecentViolations(ip, now) >= t.config.ViolationLimit && !t.permanent[ip] {
		if _, already := t.banned[ip]; !already {
			banned = true
			if len(t.banned) >= t.config.PermanentAfter {
				t.permanent[ip] = true
				perm = true
			} else {
				until = now.Add(t.config.BanDuration)
				t.banned[ip] = until
			}
			if t.store != nil {
				t.store.SaveBan(ip, until, perm)
			}
		}
	}
	cb := t.onBan
	t.mu.Unlock()
	if banned && cb != nil {
		cb(ip, reason, until)
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
