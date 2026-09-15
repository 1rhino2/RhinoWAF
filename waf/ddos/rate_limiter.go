package ddos

import (
	"net/http"
	"rhinowaf/waf/geo"
	"rhinowaf/waf/security"
)

// AllowL7 checks if an IP can make HTTP requests
func AllowL7(ip string) bool {
	ipMgr := GetIPManager()

	// Whitelisted IPs bypass all checks
	if ipMgr.IsWhitelisted(ip) {
		return true
	}

	// Check if this is from localhost (testing/development)
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return true
	}

	// Manually banned IPs are blocked immediately
	if ipMgr.IsBanned(ip) {
		entry := tracker.GetOrCreate(ip)
		entry.mu.Lock()
		LogReputationBlock(ip, entry)
		entry.mu.Unlock()
		return false
	}

	// Check geolocation rules
	countryCode := geo.GetCountryCode(ip)
	geoAction := ipMgr.CheckGeoAccess(countryCode)
	if geoAction == "block" {
		LogGeoBlock(ip, countryCode)
		return false
	}

	// Check if IP is throttled
	if throttled, percent := ipMgr.IsThrottled(ip); throttled {
		adjustedLimit := (cfg.Layer7Limit * (100 - percent)) / 100
		if tracker.RequestCount(ip) > adjustedLimit*cfg.RateWindowSec {
			return false
		}
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
	throttle := globalTracker.GetThrottleMultiplier()
	adjustedLimit := int(float64(cfg.Layer7Limit) * throttle)

	// Check if IP is hitting limits suspiciously fast
	reqs := tracker.RequestCount(ip)
	if reqs > cfg.SuspiciousIPThreshold {
		globalTracker.MarkSuspicious(ip)
		tracker.markSuspicious(ip)
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
	throttle := globalTracker.GetThrottleMultiplier()

	if throttle < 1.0 {
		adjustedLimit := int(float64(cfg.Layer4Limit) * throttle)
		if tracker.ConnectionCount(ip) > adjustedLimit*cfg.RateWindowSec {
			return false
		}
	}

	return tracker.CheckRateLimit(ip, false)
}

// GetIP extracts the real client IP from a request. X-Forwarded-For and
// friends are only honored when the connection comes from a trusted proxy
// (see security.SetTrustedProxies), otherwise anyone could spoof their way
// past bans and rate limits with one header.
func GetIP(r *http.Request) string {
	return security.GetRealIP(r)
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
