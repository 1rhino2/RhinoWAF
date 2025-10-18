package ddos

import (
	"sync"
	"sync/atomic"
	"time"
)

// GlobalTracker monitors server-wide metrics for distributed DDoS detection
type GlobalTracker struct {
	mu sync.RWMutex

	// Real-time metrics
	totalRequests        int64 // Atomic counter
	totalConnections     int64 // Atomic counter
	activeIPs            map[string]bool
	requestTimestamps    []int64 // Sliding window of all requests
	connectionTimestamps []int64

	// Adaptive throttling state
	isUnderAttack      bool
	attackStartTime    int64
	throttleLevel      int // 0 = normal, 1-5 = increasing restrictions
	lastThrottleChange int64

	// Attack pattern detection
	suspiciousIPs  map[string]int64 // IP -> first suspicious time
	blockedIPCount int
}

var globalTracker *GlobalTracker

func init() {
	globalTracker = &GlobalTracker{
		activeIPs:            make(map[string]bool),
		requestTimestamps:    make([]int64, 0, 10000),
		connectionTimestamps: make([]int64, 0, 5000),
		suspiciousIPs:        make(map[string]int64),
		totalRequests:        0,
		totalConnections:     0,
		throttleLevel:        0,
	}
	go globalTracker.monitorLoop()
}

// RecordGlobalRequest tracks a request in global statistics
func (gt *GlobalTracker) RecordGlobalRequest(ip string) bool {
	atomic.AddInt64(&gt.totalRequests, 1)
	now := nowUnix()

	gt.mu.Lock()
	defer gt.mu.Unlock()

	// Track active IPs
	gt.activeIPs[ip] = true

	// Sliding window for request timestamps
	var filtered []int64
	for _, ts := range gt.requestTimestamps {
		if ts > now-int64(cfg.RateWindowSec) {
			filtered = append(filtered, ts)
		}
	}
	filtered = append(filtered, now)
	gt.requestTimestamps = filtered

	// Check global rate limit
	reqsPerSec := len(gt.requestTimestamps) / cfg.RateWindowSec
	if reqsPerSec > cfg.GlobalRateLimit {
		gt.triggerAdaptiveThrottling()
		return false
	}

	// Check concurrent IP limit
	if len(gt.activeIPs) > cfg.MaxConcurrentIPs {
		gt.triggerAdaptiveThrottling()
		// Don't block, but mark as under attack
	}

	return true
}

// RecordGlobalConnection tracks a connection in global statistics
func (gt *GlobalTracker) RecordGlobalConnection(ip string) bool {
	atomic.AddInt64(&gt.totalConnections, 1)
	now := nowUnix()

	gt.mu.Lock()
	defer gt.mu.Unlock()

	// Sliding window for connection timestamps
	var filtered []int64
	for _, ts := range gt.connectionTimestamps {
		if ts > now-int64(cfg.RateWindowSec) {
			filtered = append(filtered, ts)
		}
	}
	filtered = append(filtered, now)
	gt.connectionTimestamps = filtered

	// Check global connection limit
	activeConns := len(gt.connectionTimestamps)
	if activeConns > cfg.GlobalConnectionLimit {
		gt.triggerAdaptiveThrottling()
		return false
	}

	return true
}

// MarkSuspicious flags an IP as potentially part of distributed attack
func (gt *GlobalTracker) MarkSuspicious(ip string) {
	if !cfg.EnableAdaptiveThrottling {
		return
	}

	gt.mu.Lock()
	defer gt.mu.Unlock()

	now := nowUnix()
	if _, exists := gt.suspiciousIPs[ip]; !exists {
		gt.suspiciousIPs[ip] = now
	}

	// If too many suspicious IPs, trigger distributed DDoS response
	if len(gt.suspiciousIPs) > 100 {
		gt.triggerAdaptiveThrottling()
	}
}

// triggerAdaptiveThrottling enables attack mode (must be called with lock held)
func (gt *GlobalTracker) triggerAdaptiveThrottling() {
	if !cfg.EnableAdaptiveThrottling {
		return
	}

	now := nowUnix()

	if !gt.isUnderAttack {
		gt.isUnderAttack = true
		gt.attackStartTime = now
		gt.throttleLevel = 1
		gt.lastThrottleChange = now

		// Log the detection
		LogDistributedAttack()
	} else {
		// Escalate throttle level every 30 seconds
		if now-gt.lastThrottleChange > 30 && gt.throttleLevel < 5 {
			gt.throttleLevel++
			gt.lastThrottleChange = now
		}
	}
}

// GetThrottleMultiplier returns the current throttle factor (1.0 = normal, 0.2 = severe)
func (gt *GlobalTracker) GetThrottleMultiplier() float64 {
	gt.mu.RLock()
	defer gt.mu.RUnlock()

	if !gt.isUnderAttack {
		return 1.0
	}

	// Progressively reduce limits
	switch gt.throttleLevel {
	case 1:
		return 0.8 // 80% of normal limits
	case 2:
		return 0.6 // 60%
	case 3:
		return 0.4 // 40%
	case 4:
		return 0.3 // 30%
	case 5:
		return 0.2 // 20% (severe attack)
	default:
		return 1.0
	}
}

// IsUnderDistributedAttack returns true if distributed DDoS detected
func (gt *GlobalTracker) IsUnderDistributedAttack() bool {
	gt.mu.RLock()
	defer gt.mu.RUnlock()
	return gt.isUnderAttack
}

// GetGlobalStats returns current global statistics
func (gt *GlobalTracker) GetGlobalStats() map[string]interface{} {
	gt.mu.RLock()
	defer gt.mu.RUnlock()

	return map[string]interface{}{
		"total_requests":      atomic.LoadInt64(&gt.totalRequests),
		"total_connections":   atomic.LoadInt64(&gt.totalConnections),
		"active_ips":          len(gt.activeIPs),
		"current_rps":         len(gt.requestTimestamps) / cfg.RateWindowSec,
		"active_connections":  len(gt.connectionTimestamps),
		"is_under_attack":     gt.isUnderAttack,
		"throttle_level":      gt.throttleLevel,
		"suspicious_ips":      len(gt.suspiciousIPs),
		"throttle_multiplier": gt.GetThrottleMultiplier(),
	}
}

// monitorLoop continuously monitors for attack patterns
func (gt *GlobalTracker) monitorLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		gt.mu.Lock()

		now := nowUnix()

		// Auto-recover from attack mode after 5 minutes of normal traffic
		if gt.isUnderAttack {
			currentRPS := len(gt.requestTimestamps) / cfg.RateWindowSec
			if currentRPS < cfg.GlobalRateLimit/2 && now-gt.attackStartTime > 300 {
				gt.isUnderAttack = false
				gt.throttleLevel = 0
				gt.suspiciousIPs = make(map[string]int64) // Clear suspicious IPs
			}
		}

		// Clean up stale suspicious IPs (older than 10 minutes)
		for ip, firstSeen := range gt.suspiciousIPs {
			if now-firstSeen > 600 {
				delete(gt.suspiciousIPs, ip)
			}
		}

		// Clean up inactive IPs (haven't made requests recently)
		// This runs in IPTracker cleanup, but we clear from activeIPs here
		if len(gt.activeIPs) > cfg.MaxConcurrentIPs*2 {
			gt.activeIPs = make(map[string]bool) // Reset if too large
		}

		gt.mu.Unlock()
	}
}

// ResetGlobalStats clears all global statistics (for testing/admin)
func (gt *GlobalTracker) ResetGlobalStats() {
	gt.mu.Lock()
	defer gt.mu.Unlock()

	atomic.StoreInt64(&gt.totalRequests, 0)
	atomic.StoreInt64(&gt.totalConnections, 0)
	gt.activeIPs = make(map[string]bool)
	gt.requestTimestamps = make([]int64, 0, 10000)
	gt.connectionTimestamps = make([]int64, 0, 5000)
	gt.suspiciousIPs = make(map[string]int64)
	gt.isUnderAttack = false
	gt.throttleLevel = 0
}
