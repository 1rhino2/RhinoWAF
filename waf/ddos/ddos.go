package ddos

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	rateWindowSec    = 2
	blockDurationSec = 120
	layer7Limit      = 40
	layer4Limit      = 80

	ipTable       = sync.Map{}
	netFloodTable = sync.Map{}
)

type ipStats struct {
	lastReqs []int64
	blocked  int64
}

type netStats struct {
	lastConns []int64
	blocked   int64
}

func AllowL7(ip string) bool {
	now := time.Now().Unix()
	val, _ := ipTable.LoadOrStore(ip, &ipStats{})
	stats := val.(*ipStats)
	if stats.blocked > now {
		return false
	}
	var filtered []int64
	for _, t := range stats.lastReqs {
		if t > now-int64(rateWindowSec) {
			filtered = append(filtered, t)
		}
	}
	filtered = append(filtered, now)
	stats.lastReqs = filtered
	if len(filtered) > layer7Limit*rateWindowSec {
		stats.blocked = now + int64(blockDurationSec)
		return false
	}
	return true
}

func AllowL4(ip string) bool {
	now := time.Now().Unix()
	val, _ := netFloodTable.LoadOrStore(ip, &netStats{})
	stats := val.(*netStats)
	if stats.blocked > now {
		return false
	}
	var filtered []int64
	for _, t := range stats.lastConns {
		if t > now-int64(rateWindowSec) {
			filtered = append(filtered, t)
		}
	}
	filtered = append(filtered, now)
	stats.lastConns = filtered
	if len(filtered) > layer4Limit*rateWindowSec {
		stats.blocked = now + int64(blockDurationSec)
		return false
	}
	return true
}

func GetIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
} // If you skid, I will commit my white payload into your ass.
