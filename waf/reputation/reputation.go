package reputation

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// Config holds reputation API configuration
type Config struct {
	Enabled           bool   `json:"enabled"`
	Provider          string `json:"provider"`           // "abuseipdb", "ipqualityscore", "both"
	AbuseIPDBKey      string `json:"abuseipdb_key"`      // API key for AbuseIPDB
	IPQualityScoreKey string `json:"ipqualityscore_key"` // API key for IPQualityScore
	CacheDuration     int    `json:"cache_duration"`     // Cache duration in minutes (default: 60)
	ScoreThreshold    int    `json:"score_threshold"`    // Score threshold for blocking (0-100, default: 75)
	AutoBlock         bool   `json:"auto_block"`         // Automatically block IPs above threshold
	AutoChallenge     bool   `json:"auto_challenge"`     // Challenge IPs above threshold/2
	Timeout           int    `json:"timeout"`            // HTTP timeout in seconds (default: 5)
}

// ReputationScore represents an IP's reputation
type ReputationScore struct {
	IP              string
	Score           int // 0-100, higher = worse
	IsProxy         bool
	IsTor           bool
	IsHosting       bool
	IsVPN           bool
	CountryCode     string
	AbuseConfidence int // AbuseIPDB confidence
	FraudScore      int // IPQualityScore fraud score
	LastChecked     time.Time
	Provider        string // Which API provided this data
}

// Checker handles IP reputation checks
type Checker struct {
	config Config
	client *http.Client
	cache  map[string]*ReputationScore
	mu     sync.RWMutex
}

// NewChecker creates a new reputation checker
func NewChecker(config Config) *Checker {
	if config.CacheDuration == 0 {
		config.CacheDuration = 60
	}
	if config.ScoreThreshold == 0 {
		config.ScoreThreshold = 75
	}
	if config.Timeout == 0 {
		config.Timeout = 5
	}

	checker := &Checker{
		config: config,
		client: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
		cache: make(map[string]*ReputationScore),
	}

	// Start cache cleanup goroutine
	go checker.cleanupCache()

	return checker
}

// Check checks an IP's reputation
func (c *Checker) Check(ip string) (*ReputationScore, error) {
	if !c.config.Enabled {
		return nil, fmt.Errorf("reputation checking disabled")
	}

	// Check cache first
	if score := c.getFromCache(ip); score != nil {
		return score, nil
	}

	var score *ReputationScore
	var err error

	// Check based on provider
	switch c.config.Provider {
	case "abuseipdb":
		score, err = c.checkAbuseIPDB(ip)
	case "ipqualityscore":
		score, err = c.checkIPQualityScore(ip)
	case "both":
		// Try both and use worst score
		score1, _ := c.checkAbuseIPDB(ip)
		score2, _ := c.checkIPQualityScore(ip)
		if score1 != nil && score2 != nil {
			if score1.Score > score2.Score {
				score = score1
			} else {
				score = score2
			}
			score.Provider = "both"
		} else if score1 != nil {
			score = score1
		} else {
			score = score2
		}
	default:
		return nil, fmt.Errorf("unknown provider: %s", c.config.Provider)
	}

	if err != nil {
		return nil, err
	}

	// Cache the result
	c.putInCache(ip, score)

	return score, nil
}

func (c *Checker) checkAbuseIPDB(ip string) (*ReputationScore, error) {
	if c.config.AbuseIPDBKey == "" {
		return nil, fmt.Errorf("AbuseIPDB API key not configured")
	}

	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Key", c.config.AbuseIPDBKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("AbuseIPDB API error: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			IsWhitelisted        bool   `json:"isWhitelisted"`
			IsTor                bool   `json:"isTor"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	score := &ReputationScore{
		IP:              ip,
		Score:           result.Data.AbuseConfidenceScore,
		IsTor:           result.Data.IsTor,
		CountryCode:     result.Data.CountryCode,
		AbuseConfidence: result.Data.AbuseConfidenceScore,
		LastChecked:     time.Now(),
		Provider:        "abuseipdb",
	}

	return score, nil
}

func (c *Checker) checkIPQualityScore(ip string) (*ReputationScore, error) {
	if c.config.IPQualityScoreKey == "" {
		return nil, fmt.Errorf("IPQualityScore API key not configured")
	}

	url := fmt.Sprintf("https://ipqualityscore.com/api/json/ip/%s/%s", c.config.IPQualityScoreKey, ip)

	resp, err := c.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("IPQualityScore API error: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Success     bool   `json:"success"`
		Message     string `json:"message"`
		FraudScore  int    `json:"fraud_score"`
		CountryCode string `json:"country_code"`
		Proxy       bool   `json:"proxy"`
		VPN         bool   `json:"vpn"`
		Tor         bool   `json:"tor"`
		Host        string `json:"host"`
		ISP         string `json:"ISP"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if !result.Success {
		return nil, fmt.Errorf("IPQualityScore API error: %s", result.Message)
	}

	score := &ReputationScore{
		IP:          ip,
		Score:       result.FraudScore,
		IsProxy:     result.Proxy,
		IsVPN:       result.VPN,
		IsTor:       result.Tor,
		CountryCode: result.CountryCode,
		FraudScore:  result.FraudScore,
		LastChecked: time.Now(),
		Provider:    "ipqualityscore",
	}

	return score, nil
}

func (c *Checker) getFromCache(ip string) *ReputationScore {
	c.mu.RLock()
	defer c.mu.RUnlock()

	score, exists := c.cache[ip]
	if !exists {
		return nil
	}

	// Check if cache expired
	if time.Since(score.LastChecked) > time.Duration(c.config.CacheDuration)*time.Minute {
		return nil
	}

	return score
}

func (c *Checker) putInCache(ip string, score *ReputationScore) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[ip] = score
}

func (c *Checker) cleanupCache() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for ip, score := range c.cache {
			if now.Sub(score.LastChecked) > time.Duration(c.config.CacheDuration)*time.Minute {
				delete(c.cache, ip)
			}
		}
		c.mu.Unlock()
	}
}

// ShouldBlock determines if an IP should be blocked based on reputation
func (c *Checker) ShouldBlock(ip string) bool {
	score, err := c.Check(ip)
	if err != nil {
		log.Printf("Reputation check failed for %s: %v", ip, err)
		return false
	}

	return c.config.AutoBlock && score.Score >= c.config.ScoreThreshold
}

// ShouldChallenge determines if an IP should be challenged based on reputation
func (c *Checker) ShouldChallenge(ip string) bool {
	score, err := c.Check(ip)
	if err != nil {
		return false
	}

	challengeThreshold := c.config.ScoreThreshold / 2
	return c.config.AutoChallenge && score.Score >= challengeThreshold && score.Score < c.config.ScoreThreshold
}

// GetCacheStats returns cache statistics
func (c *Checker) GetCacheStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"cached_ips":     len(c.cache),
		"cache_duration": c.config.CacheDuration,
	}
}

// Global checker instance
var globalChecker *Checker

// Init initializes the global reputation checker
func Init(config Config) {
	globalChecker = NewChecker(config)
	if config.Enabled {
		log.Printf("IP reputation checking enabled: provider=%s, threshold=%d", config.Provider, config.ScoreThreshold)
	}
}

// CheckIP checks an IP using the global checker
func CheckIP(ip string) (*ReputationScore, error) {
	if globalChecker == nil {
		return nil, fmt.Errorf("reputation checker not initialized")
	}
	return globalChecker.Check(ip)
}

// ShouldBlockIP checks if an IP should be blocked
func ShouldBlockIP(ip string) bool {
	if globalChecker == nil {
		return false
	}
	return globalChecker.ShouldBlock(ip)
}

// ShouldChallengeIP checks if an IP should be challenged
func ShouldChallengeIP(ip string) bool {
	if globalChecker == nil {
		return false
	}
	return globalChecker.ShouldChallenge(ip)
}
