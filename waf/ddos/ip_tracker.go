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

// IPEntry stores all the juicy details about an IP
type IPEntry struct {
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
	t.mu.RLock()
	entry, exists := t.entries[ip]
	t.mu.RUnlock()

	if exists {
		entry.LastSeen = time.Now().Unix()
		return entry
	}

	t.mu.Lock()
	// Double check after acquiring write lock
	if entry, exists = t.entries[ip]; exists {
		t.mu.Unlock()
		entry.LastSeen = time.Now().Unix()
		return entry
	}

	now := time.Now().Unix()
	entry = &IPEntry{
		Requests:         make([]int64, 0, cfg.Layer7Limit),
		Connections:      make([]int64, 0, cfg.Layer4Limit),
		FirstSeen:        now,
		LastSeen:         now,
		Reputation:       0, // Start neutral
		ActiveConns:      make(map[string]*ConnectionInfo),
		SlowConnWarnings: 0,
		BytesSent:        0,
		LastByteTime:     now,
		IsSuspicious:     false,
		SuspiciousScore:  0,
	}
	t.entries[ip] = entry
	t.mu.Unlock()

	return entry
}

// IsBlocked checks if an IP is currently blocked
func (t *IPTracker) IsBlocked(ip string) bool {
	entry := t.GetOrCreate(ip)
	now := time.Now().Unix()

	if entry.BlockedUntil > now {
		return true
	}

	if entry.Reputation <= cfg.ReputationThreshold {
		entry.BlockedUntil = now + int64(cfg.BlockDurationSec*2)
		entry.ViolationCount++
		LogReputationBlock(ip, entry) // Log reputation-based block
		return true
	}

	return false
}

// RecordRequest logs a new request for rate limiting
func (t *IPTracker) RecordRequest(ip string) {
	entry := t.GetOrCreate(ip)
	now := time.Now().Unix()
	var filtered []int64
	for _, ts := range entry.Requests {
		if ts > now-int64(cfg.RateWindowSec) {
			filtered = append(filtered, ts)
		}
	}
	filtered = append(filtered, now)
	entry.Requests = filtered
}

// RecordConnection logs a new connection for L4 tracking
func (t *IPTracker) RecordConnection(ip string) {
	entry := t.GetOrCreate(ip)
	now := time.Now().Unix()

	var filtered []int64
	for _, ts := range entry.Connections {
		if ts > now-int64(cfg.RateWindowSec) {
			filtered = append(filtered, ts)
		}
	}
	filtered = append(filtered, now)
	entry.Connections = filtered
}

// CheckRateLimit returns true if IP is within limits
// CheckRateLimit returns true if IP is within limits
func (t *IPTracker) CheckRateLimit(ip string, layer7 bool) bool {
	entry := t.GetOrCreate(ip)
	now := time.Now().Unix()

	if layer7 {
		reqs := len(entry.Requests)
		limit := cfg.Layer7Limit * cfg.RateWindowSec

		if reqs > cfg.BurstLimit {
			entry.BlockedUntil = now + int64(cfg.BlockDurationSec)
			entry.Reputation -= 10
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

// GetStats returns current tracking stats
func (t *IPTracker) GetStats() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	blocked := 0
	tracked := len(t.entries)
	now := time.Now().Unix()

	for _, entry := range t.entries {
		if entry.BlockedUntil > now {
			blocked++
		}
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
		// Clean up stale active connections (Slowloris)
		for connID, connInfo := range entry.ActiveConns {
			if now-connInfo.StartTime > maxConnTime {
				delete(entry.ActiveConns, connID)
			}
		}

		// Remove IPs that haven't been seen in a while and aren't blocked
		if entry.LastSeen < now-staleThreshold && entry.BlockedUntil < now && len(entry.ActiveConns) == 0 {
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
	t.mu.RLock()
	entry, exists := t.entries[ip]
	t.mu.RUnlock()

	if !exists {
		return map[string]interface{}{"exists": false}
	}

	now := time.Now().Unix()
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
	if len(entry.ActiveConns) >= cfg.SlowLorisMaxConnsPerIP {
		entry.BlockedUntil = now + int64(cfg.BlockDurationSec)
		entry.Reputation -= 8
		entry.ViolationCount++
		entry.SlowConnWarnings++
		return false
	}

	entry.ActiveConns[connID] = &ConnectionInfo{
		StartTime:      now,
		LastActivity:   now,
		BytesReceived:  0,
		HeaderComplete: false,
		IsSlowLoris:    false,
	}
	return true
}

// EndConnection marks a connection as finished
func (t *IPTracker) EndConnection(ip string, connID string) {
	t.mu.RLock()
	entry, exists := t.entries[ip]
	t.mu.RUnlock()

	if !exists {
		return
	}

	delete(entry.ActiveConns, connID)
}

// CheckSlowConnections detects Slowloris attacks
func (t *IPTracker) CheckSlowConnections(ip string) bool {
	entry := t.GetOrCreate(ip)
	now := time.Now().Unix()
	maxTime := int64(cfg.SlowLorisMaxConnTime)
	minBytesPerSec := int64(cfg.SlowLorisMinBytesPerSec)

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
		for connID, connInfo := range entry.ActiveConns {
			if now-connInfo.StartTime > maxTime {
				delete(entry.ActiveConns, connID)
			}
		}
	}
}

// UpdateConnectionActivity updates bytes received for a connection
func (t *IPTracker) UpdateConnectionActivity(ip string, connID string, bytes int64) {
	t.mu.RLock()
	entry, exists := t.entries[ip]
	t.mu.RUnlock()

	if !exists {
		return
	}

	if connInfo, ok := entry.ActiveConns[connID]; ok {
		connInfo.LastActivity = time.Now().Unix()
		connInfo.BytesReceived += bytes
		entry.BytesSent += bytes
		entry.LastByteTime = time.Now().Unix()
	}
}

// MarkHeadersComplete marks that HTTP headers have been fully received
func (t *IPTracker) MarkHeadersComplete(ip string, connID string) {
	t.mu.RLock()
	entry, exists := t.entries[ip]
	t.mu.RUnlock()

	if !exists {
		return
	}

	if connInfo, ok := entry.ActiveConns[connID]; ok {
		connInfo.HeaderComplete = true
	}
}
