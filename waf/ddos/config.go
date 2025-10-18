package ddos

import "time"

// Config holds all the DDoS protection settings
type Config struct {
	RateWindowSec       int
	BlockDurationSec    int
	Layer7Limit         int
	Layer4Limit         int
	BurstLimit          int
	ReputationThreshold int
	CleanupIntervalSec  int

	// Better Slowloris Protection
	SlowLorisMaxConnTime    int // Max seconds a connection can stay open
	SlowLorisMaxConnsPerIP  int // Max concurrent slow connections per IP
	SlowLorisMinBytesPerSec int // Minimum bytes/sec to avoid slow detection
	SlowLorisHeaderTimeout  int // Max seconds to send headers
	SlowLorisBodyTimeout    int // Max seconds to send body

	// DDoS(ACTUALLY DISTRIBUTED SO LIKE 50K+ IP's)Protection
	GlobalRateLimit          int  // Max total requests per second (all IPs)
	GlobalConnectionLimit    int  // Max total concurrent connections
	EnableAdaptiveThrottling bool // Auto-lower limits under attack
	SuspiciousIPThreshold    int  // Mark IP suspicious after N requests in window
	MaxConcurrentIPs         int  // Max unique IPs allowed concurrently
}

// DefaultConfig returns sensible defaults for most apps
func DefaultConfig() *Config {
	return &Config{
		RateWindowSec:       2,
		BlockDurationSec:    120,
		Layer7Limit:         40,
		Layer4Limit:         80,
		BurstLimit:          100,
		ReputationThreshold: -50,
		CleanupIntervalSec:  300, // 5 min cleanup cycle

		// Enhanced Slowloris Protection
		SlowLorisMaxConnTime:    20,  // 20 seconds max per connection
		SlowLorisMaxConnsPerIP:  5,   // Max 5 slow connections per IP
		SlowLorisMinBytesPerSec: 100, // Must send 100+ bytes/sec
		SlowLorisHeaderTimeout:  10,  // 10 seconds to send headers
		SlowLorisBodyTimeout:    30,  // 30 seconds to send body

		// Distributed DDoS Protection
		GlobalRateLimit:          10000, // 10K req/s total (all IPs)
		GlobalConnectionLimit:    5000,  // 5K concurrent connections max
		EnableAdaptiveThrottling: true,  // Auto-reduce limits under attack
		SuspiciousIPThreshold:    30,    // Flag IP after 30 req in 2s
		MaxConcurrentIPs:         1000,  // Max 1000 unique IPs at once
	}
}

// StrictConfig returns more aggressive protection
func StrictConfig() *Config {
	return &Config{
		RateWindowSec:       2,
		BlockDurationSec:    300,
		Layer7Limit:         20,
		Layer4Limit:         40,
		BurstLimit:          50,
		ReputationThreshold: -30,
		CleanupIntervalSec:  180,

		// Stricter Slowloris Protection
		SlowLorisMaxConnTime:    10,  // 10 seconds max per connection
		SlowLorisMaxConnsPerIP:  3,   // Max 3 slow connections per IP
		SlowLorisMinBytesPerSec: 200, // Must send 200+ bytes/sec
		SlowLorisHeaderTimeout:  5,   // 5 seconds to send headers
		SlowLorisBodyTimeout:    15,  // 15 seconds to send body

		// Stricter Distributed DDoS Protection
		GlobalRateLimit:          5000, // 5K req/s total
		GlobalConnectionLimit:    2000, // 2K concurrent connections
		EnableAdaptiveThrottling: true,
		SuspiciousIPThreshold:    15,  // Flag IP after 15 req in 2s
		MaxConcurrentIPs:         500, // Max 500 unique IPs at once
	}
}

// Global config instance
var cfg *Config

func init() {
	cfg = DefaultConfig()
}

// InitWithConfig applies a custom config (call before starting server)
func InitWithConfig(c *Config) {
	if c != nil {
		cfg = c
	}
}

// SetConfig allows runtime config changes (alias for InitWithConfig)
func SetConfig(c *Config) {
	InitWithConfig(c)
}

// GetConfig returns current config
func GetConfig() *Config {
	return cfg
}

// Helper for consistent time handling
func nowUnix() int64 {
	return time.Now().Unix()
}
