package ddos

import (
	"net"
	"net/http"
	"strings"
)

// AllowL7 checks if an IP can make HTTP requests
func AllowL7(ip string) bool {
	// Check IP management rules first (highest priority)
	ipMgr := GetIPManager()

	// Whitelisted IPs bypass all checks
	if ipMgr.IsWhitelisted(ip) {
		return true
	}

	// Manually banned IPs are blocked immediately
	if ipMgr.IsBanned(ip) {
		LogReputationBlock(ip, tracker.GetOrCreate(ip))
		return false
	}

	// Check global limits first (distributed DDoS protection)
	if !globalTracker.RecordGlobalRequest(ip) {
		return false
	}

	if tracker.IsBlocked(ip) {
		return false
	}

	// Check for Slowloris attack
	if !tracker.CheckSlowConnections(ip) {
		return false
	}

	tracker.RecordRequest(ip)

	// Apply adaptive throttling if under attack
	entry := tracker.GetOrCreate(ip)
	throttle := globalTracker.GetThrottleMultiplier()
	adjustedLimit := int(float64(cfg.Layer7Limit) * throttle)

	// Check if IP is hitting limits suspiciously fast
	reqs := len(entry.Requests)
	if reqs > cfg.SuspiciousIPThreshold {
		globalTracker.MarkSuspicious(ip)
		entry.IsSuspicious = true
		entry.SuspiciousScore++
	}

	// Use adjusted limit during attacks
	if throttle < 1.0 && reqs > adjustedLimit*cfg.RateWindowSec {
		return false
	}

	return tracker.CheckRateLimit(ip, true)
}

// AllowL4 checks if an IP can establish connections
func AllowL4(ip string) bool {
	// Check global connection limits (distributed DDoS protection)
	if !globalTracker.RecordGlobalConnection(ip) {
		return false
	}

	if tracker.IsBlocked(ip) {
		return false
	}

	tracker.RecordConnection(ip)

	// Adaptive throttling affects L4 limits too
	entry := tracker.GetOrCreate(ip)
	throttle := globalTracker.GetThrottleMultiplier()

	if throttle < 1.0 {
		adjustedLimit := int(float64(cfg.Layer4Limit) * throttle)
		conns := len(entry.Connections)
		if conns > adjustedLimit*cfg.RateWindowSec {
			return false
		}
	}

	return tracker.CheckRateLimit(ip, false)
}

// GetIP extracts the real client IP from a request
// Handles proxies, load balancers, and direct connections
func GetIP(r *http.Request) string {
	// Check X-Forwarded-For first (most common proxy header)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Check X-Real-IP (nginx and others)
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return strings.TrimSpace(realIP)
	}

	// Check CF-Connecting-IP (Cloudflare)
	cfIP := r.Header.Get("CF-Connecting-IP")
	if cfIP != "" {
		return strings.TrimSpace(cfIP)
	}

	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If split fails, just return the whole thing
		return r.RemoteAddr
	}

	return ip
}

// GetTracker returns the global IP tracker (for monitoring/admin)
func GetTracker() *IPTracker {
	return tracker
}

// ResetIP removes all tracking data for an IP (whitelist feature)
func ResetIP(ip string) {
	tracker.ResetIP(ip)
}

// GetStats returns current DDoS protection statistics
func GetStats() map[string]interface{} {
	return tracker.GetStats()
}

// GetIPInfo returns detailed info about a specific IP
func GetIPInfo(ip string) map[string]interface{} {
	return tracker.GetIPInfo(ip)
}

// StartConnection marks the start of a connection (Slowloris protection)
func StartConnection(ip string, connID string) bool {
	return tracker.StartConnection(ip, connID)
}

// EndConnection marks a connection as finished
func EndConnection(ip string, connID string) {
	tracker.EndConnection(ip, connID)
}

// Skidders don't deserve nice things, but we keep the code clean anyway
