package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	customCounters   = make(map[string]*prometheus.CounterVec)
	customGauges     = make(map[string]*prometheus.GaugeVec)
	customHistograms = make(map[string]*prometheus.HistogramVec)
	customMu         sync.RWMutex
)

var (
	// Request metrics
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rhinowaf_requests_total",
			Help: "Total number of HTTP requests processed by RhinoWAF",
		},
		[]string{"method", "path"},
	)

	RequestsBlocked = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rhinowaf_requests_blocked_total",
			Help: "Total number of requests blocked by RhinoWAF",
		},
		[]string{"method", "reason"},
	)

	RequestsAllowed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "rhinowaf_requests_allowed_total",
			Help: "Total number of requests allowed through RhinoWAF",
		},
	)

	RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "rhinowaf_request_duration_seconds",
			Help:    "Request processing duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "status"},
	)

	// Challenge system metrics
	ChallengesIssued = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rhinowaf_challenges_issued_total",
			Help: "Total number of challenges issued by type",
		},
		[]string{"type"},
	)

	ChallengesPassed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rhinowaf_challenges_passed_total",
			Help: "Total number of challenges successfully completed by type",
		},
		[]string{"type"},
	)

	ChallengesFailed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rhinowaf_challenges_failed_total",
			Help: "Total number of failed challenge attempts by type",
		},
		[]string{"type"},
	)

	ChallengeSessions = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "rhinowaf_challenge_sessions_active",
			Help: "Number of active challenge sessions",
		},
	)

	// Fingerprint metrics
	FingerprintsCollected = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "rhinowaf_fingerprints_collected_total",
			Help: "Total number of browser fingerprints collected",
		},
	)

	FingerprintsBlocked = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rhinowaf_fingerprints_blocked_total",
			Help: "Total number of requests blocked based on fingerprint",
		},
		[]string{"reason"},
	)

	FingerprintRateLimited = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "rhinowaf_fingerprint_rate_limited_total",
			Help: "Total number of fingerprint collection requests rate limited",
		},
	)

	ActiveFingerprints = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "rhinowaf_fingerprints_active",
			Help: "Number of active fingerprints being tracked",
		},
	)

	SuspiciousFingerprints = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "rhinowaf_fingerprints_suspicious",
			Help: "Number of fingerprints flagged as suspicious",
		},
	)

	// Rate limiting metrics
	RateLimitExceeded = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rhinowaf_rate_limit_exceeded_total",
			Help: "Total number of requests exceeding rate limits",
		},
		[]string{"limit_type"},
	)

	// Header validation metrics
	HeaderValidationFailed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rhinowaf_header_validation_failed_total",
			Help: "Total number of requests with invalid headers",
		},
		[]string{"reason"},
	)

	// IP rule metrics
	IPRuleBlocked = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rhinowaf_ip_rule_blocked_total",
			Help: "Total number of requests blocked by IP rules",
		},
		[]string{"rule_type"},
	)

	BannedIPs = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "rhinowaf_banned_ips",
			Help: "Number of currently banned IPs",
		},
	)

	WhitelistedIPs = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "rhinowaf_whitelisted_ips",
			Help: "Number of currently whitelisted IPs",
		},
	)

	// Geo-blocking metrics
	GeoBlocked = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rhinowaf_geo_blocked_total",
			Help: "Total number of requests blocked by geo-location",
		},
		[]string{"country", "action"},
	)

	// Malicious input detection metrics
	MaliciousInputBlocked = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rhinowaf_malicious_input_blocked_total",
			Help: "Total number of requests blocked for malicious input",
		},
		[]string{"vector"},
	)

	// Configuration reload metrics
	ConfigReloads = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rhinowaf_config_reloads_total",
			Help: "Total number of configuration reloads by type",
		},
		[]string{"config_type"},
	)
)

func RegisterCustomCounter(name, help string, labels []string) *prometheus.CounterVec {
	customMu.Lock()
	defer customMu.Unlock()

	if counter, exists := customCounters[name]; exists {
		return counter
	}

	counter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: name,
			Help: help,
		},
		labels,
	)

	customCounters[name] = counter
	return counter
}

func RegisterCustomGauge(name, help string, labels []string) *prometheus.GaugeVec {
	customMu.Lock()
	defer customMu.Unlock()

	if gauge, exists := customGauges[name]; exists {
		return gauge
	}

	gauge := promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: name,
			Help: help,
		},
		labels,
	)

	customGauges[name] = gauge
	return gauge
}

func RegisterCustomHistogram(name, help string, labels []string, buckets []float64) *prometheus.HistogramVec {
	customMu.Lock()
	defer customMu.Unlock()

	if histogram, exists := customHistograms[name]; exists {
		return histogram
	}

	if len(buckets) == 0 {
		buckets = prometheus.DefBuckets
	}

	histogram := promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    name,
			Help:    help,
			Buckets: buckets,
		},
		labels,
	)

	customHistograms[name] = histogram
	return histogram
}

func GetCustomCounter(name string) (*prometheus.CounterVec, bool) {
	customMu.RLock()
	defer customMu.RUnlock()
	counter, exists := customCounters[name]
	return counter, exists
}

func GetCustomGauge(name string) (*prometheus.GaugeVec, bool) {
	customMu.RLock()
	defer customMu.RUnlock()
	gauge, exists := customGauges[name]
	return gauge, exists
}

func GetCustomHistogram(name string) (*prometheus.HistogramVec, bool) {
	customMu.RLock()
	defer customMu.RUnlock()
	histogram, exists := customHistograms[name]
	return histogram, exists
}
