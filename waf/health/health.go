package health

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"
)

var startTime time.Time

func init() {
	startTime = time.Now()
}

// HealthStatus represents the current health status of the WAF
type HealthStatus struct {
	Status        string     `json:"status"`
	Version       string     `json:"version"`
	Uptime        string     `json:"uptime"`
	UptimeSeconds int64      `json:"uptime_seconds"`
	Timestamp     string     `json:"timestamp"`
	System        SystemInfo `json:"system"`
}

// SystemInfo contains system-level information
type SystemInfo struct {
	GoVersion    string `json:"go_version"`
	NumGoroutine int    `json:"goroutines"`
	MemoryMB     uint64 `json:"memory_mb"`
	NumCPU       int    `json:"num_cpu"`
}

// Handler returns the health check HTTP handler
func Handler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		uptime := time.Since(startTime)

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		status := HealthStatus{
			Status:        "healthy",
			Version:       version,
			Uptime:        formatUptime(uptime),
			UptimeSeconds: int64(uptime.Seconds()),
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
			System: SystemInfo{
				GoVersion:    runtime.Version(),
				NumGoroutine: runtime.NumGoroutine(),
				MemoryMB:     m.Alloc / 1024 / 1024,
				NumCPU:       runtime.NumCPU(),
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(status)
	}
}
func formatUptime(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return formatTime(days, "day") + " " + formatTime(hours, "hour")
	}
	if hours > 0 {
		return formatTime(hours, "hour") + " " + formatTime(minutes, "minute")
	}
	if minutes > 0 {
		return formatTime(minutes, "minute") + " " + formatTime(seconds, "second")
	}
	return formatTime(seconds, "second")
}

func formatTime(value int, unit string) string {
	if value == 1 {
		return "1 " + unit
	}
	return formatInt(value) + " " + unit + "s"
}

func formatInt(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
