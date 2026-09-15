// Skidders don't deserve nice things, but we keep the code clean anyway
package ddos

import (
	"sync"
	"time"
)

// ConnectionInfo tracks detailed information about a single connection
type ConnectionInfo struct {
	StartTime      int64 // When connection started
	LastActivity   int64 // Last time data was received
	BytesReceived  int64 // Total bytes received on this connection
	HeaderComplete bool  // Whether HTTP headers have been fully received
	IsSlowLoris    bool  // Detected as Slowloris attack
}

// IPTracker keeps tabs on each IP's behavior and reputation
type IPTracker struct {
	mu          sync.RWMutex
	entries     map[string]*IPEntry
	lastCleanup int64
}

// IPEntry stores all the juicy details about an IP.
// mu guards every field below it; the tracker map lock only guards the map.
// Two requests from one IP land on the same entry concurrently, so without
// this the request slices get corrupted under load.
type IPEntry struct {
	mu sync.Mutex

	Requests       []int64
	Connections    []int64
	BlockedUntil   int64
	Reputation     int
	FirstSeen      int64
	LastSeen       int64
	ViolationCount int

	// Enhanced Slowloris tracking
	ActiveConns      map[string]*ConnectionInfo // connID -> connection details
	SlowConnWarnings int                        // Count of slow connection warnings
	BytesSent        int64                      // Total bytes sent by this IP
	LastByteTime     int64                      // Last time bytes were received

	// Distributed attack indicators
	IsSuspicious    bool // Flagged as part of distributed attack
	SuspiciousScore int  // Higher = more suspicious
}

var tracker *IPTracker

func init() {
	tracker = &IPTracker{
		entries:     make(map[string]*IPEntry),
		lastCleanup: time.Now().Unix(),
	}
	go tracker.cleanupLoop()
}

// GetOrCreate returns existing entry or creates new one
func (t *IPTracker) GetOrCreate(ip string) *IPEntry {
	now := time.Now().Unix()

	t.mu.RLock()
	entry, exists := t.entries[ip]
	t.mu.RUnlock()

	if !exists {
		t.mu.Lock()
		// Double check after acquiring write lock
		if entry, exists = t.entries[ip]; !exists {
			entry = &IPEntry{
				Requests:     make([]int64, 0, cfg.Layer7Limit),
				Connections:  make([]int64, 0, cfg.Layer4Limit),
				FirstSeen:    now,
				LastSeen:     now,
				Reputation:   0, // Start neutral
				ActiveConns:  make(map[string]*ConnectionInfo),
				LastByteTime: now,
			}
			t.entries[ip] = entry
		}
		t.mu.Unlock()
	}

	entry.mu.Lock()
	entry.LastSeen = now
	entry.mu.Unlock()
	return entry
}

// get returns the entry without creating it
func (t *IPTracker) get(ip string) (*IPEntry, bool) {
	t.mu.RLock()
	entry, exists := t.entries[ip]
	t.mu.RUnlock()
	return entry, exists
}

// IsBlocked checks if an IP is currently blocked
func (t *IPTracker) IsBlocked(ip string) bool {
	entry := t.GetOrCreate(ip)
	now := time.Now().Unix()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.BlockedUntil > now {
		return true
	}

	if entry.Reputation <= cfg.ReputationThreshold {
		entry.BlockedUntil = now + int64(cfg.BlockDurationSec*2)
		entry.ViolationCount++
		// lift reputation just above the line so the block actually expires;
		// used to sit at the threshold and re-block on every request forever
		entry.Reputation = cfg.ReputationThreshold + 10
		LogReputationBlock(ip, entry) // Log reputation-based block
		return true
	}

	return false
}

// RecordRequest logs a new request for rate limiting
func (t *IPTracker) RecordRequest(ip string) {
	entry := t.GetOrCreate(ip)
	now := time.Now().Unix()

	entry.mu.Lock()
	entry.Requests = pruneWindow(entry.Requests, now)
	entry.Requests = append(entry.Requests, now)
	entry.mu.Unlock()
}

// RecordConnection logs a new connection for L4 tracking
func (t *IPTracker) RecordConnection(ip string) {
	entry := t.GetOrCreate(ip)
	now := time.Now().Unix()

	entry.mu.Lock()
	entry.Connections = pruneWindow(entry.Connections, now)
	entry.Connections = append(entry.Connections, now)
	entry.mu.Unlock()
}

// pruneWindow drops timestamps outside the rate window, in place
func pruneWindow(ts []int64, now int64) []int64 {
	cutoff := now - int64(cfg.RateWindowSec)
	keep := ts[:0]
	for _, v := range ts {
		if v > cutoff {
			keep = append(keep, v)
		}
	}
	return keep
}

// CheckRateLimit returns true if IP is within limits
func (t *IPTracker) CheckRateLimit(ip string, layer7 bool) bool {
	entry := t.GetOrCreate(ip)
	now := time.Now().Unix()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if layer7 {
		reqs := len(entry.Requests)
		limit := cfg.Layer7Limit * cfg.RateWindowSec

		if reqs > cfg.BurstLimit {
			entry.BlockedUntil = now + int64(cfg.BlockDurationSec)
			entry.Reputation -= 10
			entry.ViolationCount++
			LogBurstAttack(ip, entry, reqs)
			return false
		}

		if reqs > limit {
			entry.BlockedUntil = now + int64(cfg.BlockDurationSec)
			entry.Reputation -= 5
			entry.ViolationCount++
			LogRateLimitViolation(ip, entry, true, reqs, limit) // Log L7 rate limit
			return false
		}

		if reqs < limit/2 && entry.Reputation < 100 {
			entry.Reputation++
		}

		return true
	}

	conns := len(entry.Connections)
	limit := cfg.Layer4Limit * cfg.RateWindowSec

	if conns > cfg.BurstLimit {
		entry.BlockedUntil = now + int64(cfg.BlockDurationSec)
		entry.Reputation -= 10
		entry.ViolationCount++
		LogBurstAttack(ip, entry, conns) // Log L4 burst attack
		return false
	}

	if conns > limit {
		entry.BlockedUntil = now + int64(cfg.BlockDurationSec)
		entry.Reputation -= 5
		entry.ViolationCount++
		LogRateLimitViolation(ip, entry, false, conns, limit) // Log L4 rate limit
		return false
	}

	if conns < limit/2 && entry.Reputation < 100 {
		entry.Reputation++
	}

	return true
}

// RequestCount returns how many requests the IP made inside the current window
func (t *IPTracker) RequestCount(ip string) int {
	entry := t.GetOrCreate(ip)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return len(entry.Requests)
}

// ConnectionCount returns how many connections the IP opened inside the window
func (t *IPTracker) ConnectionCount(ip string) int {
	entry := t.GetOrCreate(ip)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return len(entry.Connections)
}

// markSuspicious flags the entry and returns the request count that did it
func (t *IPTracker) markSuspicious(ip string) {
	entry := t.GetOrCreate(ip)
	entry.mu.Lock()
	entry.IsSuspicious = true
	entry.SuspiciousScore++
	entry.mu.Unlock()
}

// GetStats returns current tracking stats
func (t *IPTracker) GetStats() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	blocked := 0
	tracked := len(t.entries)
	now := time.Now().Unix()

	for _, entry := range t.entries {
		entry.mu.Lock()
		if entry.BlockedUntil > now {
			blocked++
		}
		entry.mu.Unlock()
	}

	return map[string]interface{}{
		"tracked_ips":  tracked,
		"blocked_ips":  blocked,
		"last_cleanup": t.lastCleanup,
	}
}

func (t *IPTracker) cleanupLoop() {
	ticker := time.NewTicker(time.Duration(cfg.CleanupIntervalSec) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		t.cleanup()
	}
}

func (t *IPTracker) cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().Unix()
	staleThreshold := int64(cfg.BlockDurationSec * 3) // Keep for 3x block duration
	maxConnTime := int64(cfg.SlowLorisMaxConnTime)

	for ip, entry := range t.entries {
		entry.mu.Lock()
		// Clean up stale active connections (Slowloris)
		for connID, connInfo := range entry.ActiveConns {
			if now-connInfo.StartTime > maxConnTime {
				delete(entry.ActiveConns, connID)
			}
		}

		// Remove IPs that haven't been seen in a while and aren't blocked
		stale := entry.LastSeen < now-staleThreshold && entry.BlockedUntil < now && len(entry.ActiveConns) == 0
		entry.mu.Unlock()
		if stale {
			delete(t.entries, ip)
		}
	}

	t.lastCleanup = now
}

// ResetIP clears tracking for a specific IP (useful for whitelisting)
func (t *IPTracker) ResetIP(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, ip)
}

// GetIPInfo returns detailed info about an IP
func (t *IPTracker) GetIPInfo(ip string) map[string]interface{} {
	entry, exists := t.get(ip)
	if !exists {
		return map[string]interface{}{"exists": false}
	}

	now := time.Now().Unix()
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return map[string]interface{}{
		"exists":             true,
		"reputation":         entry.Reputation,
		"blocked":            entry.BlockedUntil > now,
		"blocked_until":      entry.BlockedUntil,
		"violation_count":    entry.ViolationCount,
		"first_seen":         entry.FirstSeen,
		"last_seen":          entry.LastSeen,
		"request_count":      len(entry.Requests),
		"connection_count":   len(entry.Connections),
		"active_conns":       len(entry.ActiveConns),
		"slow_conn_warnings": entry.SlowConnWarnings,
	}
}

// StartConnection tracks when a connection starts
func (t *IPTracker) StartConnection(ip string, connID string) bool {
	entry := t.GetOrCreate(ip)
	now := time.Now().Unix()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if len(entry.ActiveConns) >= cfg.SlowLorisMaxConnsPerIP {
		entry.BlockedUntil = now + int64(cfg.BlockDurationSec)
		entry.Reputation -= 8
		entry.ViolationCount++
		entry.SlowConnWarnings++
		return false
	}

	entry.ActiveConns[connID] = &ConnectionInfo{
		StartTime:    now,
		LastActivity: now,
	}
	return true
}

// EndConnection marks a connection as finished
func (t *IPTracker) EndConnection(ip string, connID string) {
	entry, exists := t.get(ip)
	if !exists {
		return
	}

	entry.mu.Lock()
	delete(entry.ActiveConns, connID)
	entry.mu.Unlock()
}

// CheckSlowConnections detects Slowloris attacks
func (t *IPTracker) CheckSlowConnections(ip string) bool {
	entry := t.GetOrCreate(ip)
	now := time.Now().Unix()
	maxTime := int64(cfg.SlowLorisMaxConnTime)
	minBytesPerSec := int64(cfg.SlowLorisMinBytesPerSec)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	staleConns := 0
	slowConns := 0

	for connID, connInfo := range entry.ActiveConns {
		connAge := now - connInfo.StartTime

		if connAge > maxTime {
			staleConns++
			connInfo.IsSlowLoris = true
			delete(entry.ActiveConns, connID)
			continue
		}

		if connAge > 0 {
			bytesPerSec := connInfo.BytesReceived / connAge
			if bytesPerSec < minBytesPerSec && connAge > 5 {
				slowConns++
				connInfo.IsSlowLoris = true
			}
		}

		if !connInfo.HeaderComplete && connAge > int64(cfg.SlowLorisHeaderTimeout) {
			slowConns++
			connInfo.IsSlowLoris = true
		}
	}

	totalSlowConns := staleConns + slowConns

	if totalSlowConns > 0 {
		entry.Reputation -= (totalSlowConns * 3)
		entry.SlowConnWarnings += totalSlowConns

		LogSlowlorisAttack(ip, entry, totalSlowConns)
		if totalSlowConns >= cfg.SlowLorisMaxConnsPerIP/2 {
			entry.BlockedUntil = now + int64(cfg.BlockDurationSec)
			entry.ViolationCount++
			return false
		}
	}

	return true
}

// CleanupStaleConnections removes connections that are too old
func (t *IPTracker) CleanupStaleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().Unix()
	maxTime := int64(cfg.SlowLorisMaxConnTime)

	for _, entry := range t.entries {
		entry.mu.Lock()
		for connID, connInfo := range entry.ActiveConns {
			if now-connInfo.StartTime > maxTime {
				delete(entry.ActiveConns, connID)
			}
		}
		entry.mu.Unlock()
	}
}

// UpdateConnectionActivity updates bytes received for a connection
func (t *IPTracker) UpdateConnectionActivity(ip string, connID string, bytes int64) {
	entry, exists := t.get(ip)
	if !exists {
		return
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if connInfo, ok := entry.ActiveConns[connID]; ok {
		connInfo.LastActivity = time.Now().Unix()
		connInfo.BytesReceived += bytes
		entry.BytesSent += bytes
		entry.LastByteTime = time.Now().Unix()
	}
}

// MarkHeadersComplete marks that HTTP headers have been fully received
func (t *IPTracker) MarkHeadersComplete(ip string, connID string) {
	entry, exists := t.get(ip)
	if !exists {
		return
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if connInfo, ok := entry.ActiveConns[connID]; ok {
		connInfo.HeaderComplete = true
	}
}
