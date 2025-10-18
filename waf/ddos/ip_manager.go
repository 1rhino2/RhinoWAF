package ddos

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// IPRule represents a manual IP management rule with detailed tracking
type IPRule struct {
	IP           string     `json:"ip"`
	Type         string     `json:"type"` // "ban", "whitelist", "monitor", "challenge", "throttle"
	Reason       string     `json:"reason"`
	BannedBy     string     `json:"banned_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"` // nil = permanent
	ViolationLog []string   `json:"violation_log,omitempty"`
	Notes        string     `json:"notes,omitempty"`
	Tags         []string   `json:"tags,omitempty"`
	AutoBan      bool       `json:"auto_ban"` // If true, this was an automatic ban

	// Advanced Controls
	RateLimitOverride  *int     `json:"rate_limit_override,omitempty"`  // Custom rate limit for this IP
	AllowedPaths       []string `json:"allowed_paths,omitempty"`        // Only allow these paths
	BlockedPaths       []string `json:"blocked_paths,omitempty"`        // Block these paths
	AllowedMethods     []string `json:"allowed_methods,omitempty"`      // Only allow these HTTP methods
	BlockedMethods     []string `json:"blocked_methods,omitempty"`      // Block these HTTP methods
	RequireAuth        bool     `json:"require_auth,omitempty"`         // Require authentication
	MaxConcurrentConns int      `json:"max_concurrent_conns,omitempty"` // Max simultaneous connections
	ThrottlePercent    int      `json:"throttle_percent,omitempty"`     // Reduce rate limit by X% (1-100)
	AllowedUserAgents  []string `json:"allowed_user_agents,omitempty"`  // Regex patterns for allowed UAs
	BlockedUserAgents  []string `json:"blocked_user_agents,omitempty"`  // Regex patterns for blocked UAs
	Priority           int      `json:"priority,omitempty"`             // Higher priority = checked first

	// Time-based Controls
	AllowedHours []int    `json:"allowed_hours,omitempty"` // Hours (0-23) when access is allowed
	BlockedHours []int    `json:"blocked_hours,omitempty"` // Hours when access is blocked
	AllowedDays  []string `json:"allowed_days,omitempty"`  // Days of week (Mon, Tue, etc.)
	BlockedDays  []string `json:"blocked_days,omitempty"`  // Days when access is blocked
	Timezone     string   `json:"timezone,omitempty"`      // Timezone for time checks (e.g., "America/New_York")

	// Request Pattern Controls
	AllowedQueryParams []string `json:"allowed_query_params,omitempty"` // Allowed query parameter patterns (regex)
	BlockedQueryParams []string `json:"blocked_query_params,omitempty"` // Blocked query parameter patterns
	RequiredHeaders    []string `json:"required_headers,omitempty"`     // Headers that must be present
	BlockedHeaders     []string `json:"blocked_headers,omitempty"`      // Headers that cause blocking
	AllowedReferers    []string `json:"allowed_referers,omitempty"`     // Allowed referrer patterns
	BlockedReferers    []string `json:"blocked_referers,omitempty"`     // Blocked referrer patterns
	RequireCookies     []string `json:"require_cookies,omitempty"`      // Cookies that must be present

	// Content Controls
	AllowedContentTypes []string `json:"allowed_content_types,omitempty"` // Allowed Content-Type headers
	BlockedContentTypes []string `json:"blocked_content_types,omitempty"` // Blocked Content-Type headers
	MaxUploadSize       int64    `json:"max_upload_size,omitempty"`       // Max request body size in bytes
	MaxURLLength        int      `json:"max_url_length,omitempty"`        // Max URL length
	MaxHeaderSize       int      `json:"max_header_size,omitempty"`       // Max total header size
	BlockedFileExts     []string `json:"blocked_file_exts,omitempty"`     // File extensions to block (.php, .exe)
	AllowedFileExts     []string `json:"allowed_file_exts,omitempty"`     // Only allow these file extensions

	// Behavioral Controls
	MinRequestInterval  int  `json:"min_request_interval,omitempty"`  // Min ms between requests
	MaxBurstSize        int  `json:"max_burst_size,omitempty"`        // Max requests in burst window
	BurstWindowMs       int  `json:"burst_window_ms,omitempty"`       // Burst window in milliseconds
	MaxSessionDuration  int  `json:"max_session_duration,omitempty"`  // Max session duration in seconds
	RequireValidSession bool `json:"require_valid_session,omitempty"` // Require valid session cookie
	BlockHeadless       bool `json:"block_headless,omitempty"`        // Block headless browsers
	BlockBots           bool `json:"block_bots,omitempty"`            // Block known bot user agents
	RequireJavaScript   bool `json:"require_javascript,omitempty"`    // Require JS challenge completion

	// Protocol/Network Controls
	AllowedPorts     []int    `json:"allowed_ports,omitempty"`     // Allowed destination ports
	BlockedPorts     []int    `json:"blocked_ports,omitempty"`     // Blocked destination ports
	RequireHTTPS     bool     `json:"require_https,omitempty"`     // Require HTTPS connections
	RequireHTTP2     bool     `json:"require_http2,omitempty"`     // Require HTTP/2
	BlockedProtocols []string `json:"blocked_protocols,omitempty"` // HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3
	AllowedCiphers   []string `json:"allowed_ciphers,omitempty"`   // Allowed TLS cipher suites
	MinTLSVersion    string   `json:"min_tls_version,omitempty"`   // Minimum TLS version (1.2, 1.3)

	// Custom Controls
	CustomHeaders     map[string]string `json:"custom_headers,omitempty"`     // Headers to add to response
	CustomRules       []CustomRule      `json:"custom_rules,omitempty"`       // Custom rule logic
	RateLimitByPath   map[string]int    `json:"rate_limit_by_path,omitempty"` // Different limits per path
	WhitelistOverride bool              `json:"whitelist_override,omitempty"` // Bypass all other rules
}

// CustomRule represents a custom validation rule
type CustomRule struct {
	Name          string `json:"name"`
	Type          string `json:"type"`    // "header", "query", "body", "cookie", "custom"
	Pattern       string `json:"pattern"` // Regex pattern to match
	Action        string `json:"action"`  // "allow", "block", "challenge"
	CaseSensitive bool   `json:"case_sensitive,omitempty"`
	Invert        bool   `json:"invert,omitempty"` // Invert the match
}

// GeoRule represents geolocation-based access control
type GeoRule struct {
	CountryCode     string     `json:"country_code"` // ISO 2-letter code (US, CN, RU, etc.)
	Action          string     `json:"action"`       // "allow", "block", "challenge", "throttle"
	Reason          string     `json:"reason"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	Priority        int        `json:"priority,omitempty"`
	ThrottlePercent int        `json:"throttle_percent,omitempty"` // Reduce rate by X%
	AllowedPaths    []string   `json:"allowed_paths,omitempty"`
	BlockedPaths    []string   `json:"blocked_paths,omitempty"`
}

// ASNRule represents ASN-based access control
type ASNRule struct {
	ASN             string     `json:"asn"` // Autonomous System Number
	Organization    string     `json:"organization,omitempty"`
	Action          string     `json:"action"` // "allow", "block", "challenge"
	Reason          string     `json:"reason"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	ThrottlePercent int        `json:"throttle_percent,omitempty"`
}

// GlobalRules represents global WAF policies
type GlobalRules struct {
	DefaultAction        string   `json:"default_action"`         // "allow", "challenge", "block"
	BlockProxies         bool     `json:"block_proxies"`          // Block known proxies/VPNs
	BlockTor             bool     `json:"block_tor"`              // Block Tor exit nodes
	BlockHosting         bool     `json:"block_hosting"`          // Block cloud/hosting IPs
	BlockedCountries     []string `json:"blocked_countries"`      // List of blocked country codes
	AllowedCountries     []string `json:"allowed_countries"`      // If set, only allow these countries
	RequireAuthCountries []string `json:"require_auth_countries"` // Countries that require authentication
	ChallengeCountries   []string `json:"challenge_countries"`    // Countries that get challenged first
	MaxRequestsPerIP     int      `json:"max_requests_per_ip"`    // Global max requests per IP per window
	MaxConnectionsPerIP  int      `json:"max_connections_per_ip"` // Global max connections per IP
	BlockEmptyUserAgent  bool     `json:"block_empty_user_agent"`
	BlockSuspiciousUA    bool     `json:"block_suspicious_ua"` // Block known malicious user agents

	// Enhanced Global Controls
	GlobalRateLimitWindow    int      `json:"global_rate_limit_window,omitempty"`   // Window in seconds
	BlockKnownBadBots        bool     `json:"block_known_bad_bots,omitempty"`       // Block scrapers, attackers
	AllowSearchEngineBots    bool     `json:"allow_search_engine_bots,omitempty"`   // Allow Google, Bing, etc.
	RequireValidUserAgent    bool     `json:"require_valid_user_agent,omitempty"`   // Block invalid/malformed UAs
	MaxURLLength             int      `json:"max_url_length,omitempty"`             // Global max URL length
	MaxHeaderCount           int      `json:"max_header_count,omitempty"`           // Max number of headers
	MaxCookieCount           int      `json:"max_cookie_count,omitempty"`           // Max number of cookies
	BlockSQLInjection        bool     `json:"block_sql_injection,omitempty"`        // Block SQL injection patterns
	BlockXSS                 bool     `json:"block_xss,omitempty"`                  // Block XSS patterns
	BlockPathTraversal       bool     `json:"block_path_traversal,omitempty"`       // Block ../ patterns
	BlockCommandInjection    bool     `json:"block_command_injection,omitempty"`    // Block command injection
	BlockXMLInjection        bool     `json:"block_xml_injection,omitempty"`        // Block XML/XXE attacks
	BlockSSRF                bool     `json:"block_ssrf,omitempty"`                 // Block SSRF attempts
	BlockLDAPInjection       bool     `json:"block_ldap_injection,omitempty"`       // Block LDAP injection
	BlockTemplateInjection   bool     `json:"block_template_injection,omitempty"`   // Block template injection
	RequireHTTPS             bool     `json:"require_https,omitempty"`              // Force HTTPS
	RequireModernTLS         bool     `json:"require_modern_tls,omitempty"`         // Require TLS 1.2+
	BlockOldHTTPVersions     bool     `json:"block_old_http_versions,omitempty"`    // Block HTTP/1.0
	MaxRequestBodySize       int64    `json:"max_request_body_size,omitempty"`      // Global max body size
	AllowedMethods           []string `json:"allowed_methods,omitempty"`            // Global allowed methods
	BlockedPaths             []string `json:"blocked_paths,omitempty"`              // Global blocked paths
	RateLimitByEndpoint      bool     `json:"rate_limit_by_endpoint,omitempty"`     // Separate limits per endpoint
	EnableGeoFencing         bool     `json:"enable_geo_fencing,omitempty"`         // Enable geo restrictions
	EnableASNBlocking        bool     `json:"enable_asn_blocking,omitempty"`        // Enable ASN blocking
	LogAllRequests           bool     `json:"log_all_requests,omitempty"`           // Log every request
	LogBlockedOnly           bool     `json:"log_blocked_only,omitempty"`           // Only log blocked requests
	EnableChallengeMode      bool     `json:"enable_challenge_mode,omitempty"`      // Enable challenge system
	ChallengeType            string   `json:"challenge_type,omitempty"`             // "captcha", "js", "proof-of-work"
	ChallengeDifficulty      int      `json:"challenge_difficulty,omitempty"`       // 1-10 difficulty level
	SessionTimeout           int      `json:"session_timeout,omitempty"`            // Session timeout in seconds
	EnableFingerprinting     bool     `json:"enable_fingerprinting,omitempty"`      // Track browser fingerprints
	BlockRepeatedFingerprint bool     `json:"block_repeated_fingerprint,omitempty"` // Block same fingerprint
	MaxFingerprintReuse      int      `json:"max_fingerprint_reuse,omitempty"`      // Max IPs per fingerprint
}

// IPConfig represents the JSON configuration file for IP management
type IPConfig struct {
	Version        string      `json:"version"`
	LastModified   time.Time   `json:"last_modified"`
	BannedIPs      []IPRule    `json:"banned_ips"`
	WhitelistedIPs []IPRule    `json:"whitelisted_ips"`
	MonitoredIPs   []IPRule    `json:"monitored_ips"`  // IPs to watch closely
	ChallengedIPs  []IPRule    `json:"challenged_ips"` // IPs that must pass challenge
	ThrottledIPs   []IPRule    `json:"throttled_ips"`  // IPs with reduced rate limits
	GeoRules       []GeoRule   `json:"geo_rules"`
	ASNRules       []ASNRule   `json:"asn_rules"`
	GlobalRules    GlobalRules `json:"global_rules"`
}

// IPManager handles loading, saving, and querying IP management rules
type IPManager struct {
	mu            sync.RWMutex
	configPath    string
	config        *IPConfig
	bannedMap     map[string]*IPRule
	whitelistMap  map[string]*IPRule
	monitoredMap  map[string]*IPRule
	challengedMap map[string]*IPRule
	throttledMap  map[string]*IPRule
	geoRulesMap   map[string]*GeoRule // country code -> rule
	asnRulesMap   map[string]*ASNRule // ASN -> rule
	autoSave      bool
	cleanupTimer  *time.Ticker
}

var (
	ipManager     *IPManager
	ipMgrInitOnce sync.Once
)

// InitIPManager initializes the IP management system
func InitIPManager(configPath string, autoSave bool) error {
	var initErr error

	ipMgrInitOnce.Do(func() {
		if configPath == "" {
			configPath = "./config/ip_rules.json"
		}

		ipManager = &IPManager{
			configPath:    configPath,
			bannedMap:     make(map[string]*IPRule),
			whitelistMap:  make(map[string]*IPRule),
			monitoredMap:  make(map[string]*IPRule),
			challengedMap: make(map[string]*IPRule),
			throttledMap:  make(map[string]*IPRule),
			geoRulesMap:   make(map[string]*GeoRule),
			asnRulesMap:   make(map[string]*ASNRule),
			autoSave:      autoSave,
			cleanupTimer:  time.NewTicker(1 * time.Hour),
		}

		// Try to load existing config
		if err := ipManager.load(); err != nil {
			// If file doesn't exist, create a new config
			if os.IsNotExist(err) {
				ipManager.config = &IPConfig{
					Version:        "2.0",
					LastModified:   time.Now(),
					BannedIPs:      []IPRule{},
					WhitelistedIPs: []IPRule{},
					MonitoredIPs:   []IPRule{},
					ChallengedIPs:  []IPRule{},
					ThrottledIPs:   []IPRule{},
					GeoRules:       []GeoRule{},
					ASNRules:       []ASNRule{},
					GlobalRules: GlobalRules{
						DefaultAction:        "allow",
						BlockProxies:         false,
						BlockTor:             false,
						BlockHosting:         false,
						BlockedCountries:     []string{},
						AllowedCountries:     []string{},
						RequireAuthCountries: []string{},
						ChallengeCountries:   []string{},
						MaxRequestsPerIP:     0,
						MaxConnectionsPerIP:  0,
						BlockEmptyUserAgent:  false,
						BlockSuspiciousUA:    false,
					},
				}
				if err := ipManager.save(); err != nil {
					initErr = fmt.Errorf("failed to create IP config file: %w", err)
					return
				}
			} else {
				initErr = fmt.Errorf("failed to load IP config: %w", err)
				return
			}
		}

		// Start background cleanup of expired bans
		go ipManager.cleanupExpiredRules()

		log.Printf("IP Manager initialized: %d banned, %d whitelisted, %d monitored, %d geo rules",
			len(ipManager.bannedMap), len(ipManager.whitelistMap), len(ipManager.monitoredMap), len(ipManager.geoRulesMap))
	})

	return initErr
}

// GetIPManager returns the global IP manager instance
func GetIPManager() *IPManager {
	if ipManager == nil {
		InitIPManager("", true)
	}
	return ipManager
}

// load reads the IP config from JSON file
func (m *IPManager) load() error {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.config = &IPConfig{}
	if err := json.Unmarshal(data, m.config); err != nil {
		return fmt.Errorf("failed to parse IP config: %w", err)
	}

	// Build maps for fast lookup
	m.bannedMap = make(map[string]*IPRule)
	m.whitelistMap = make(map[string]*IPRule)
	m.monitoredMap = make(map[string]*IPRule)
	m.challengedMap = make(map[string]*IPRule)
	m.throttledMap = make(map[string]*IPRule)
	m.geoRulesMap = make(map[string]*GeoRule)
	m.asnRulesMap = make(map[string]*ASNRule)

	for i := range m.config.BannedIPs {
		rule := &m.config.BannedIPs[i]
		m.bannedMap[rule.IP] = rule
	}

	for i := range m.config.WhitelistedIPs {
		rule := &m.config.WhitelistedIPs[i]
		m.whitelistMap[rule.IP] = rule
	}

	for i := range m.config.MonitoredIPs {
		rule := &m.config.MonitoredIPs[i]
		m.monitoredMap[rule.IP] = rule
	}

	for i := range m.config.ChallengedIPs {
		rule := &m.config.ChallengedIPs[i]
		m.challengedMap[rule.IP] = rule
	}

	for i := range m.config.ThrottledIPs {
		rule := &m.config.ThrottledIPs[i]
		m.throttledMap[rule.IP] = rule
	}

	for i := range m.config.GeoRules {
		rule := &m.config.GeoRules[i]
		m.geoRulesMap[rule.CountryCode] = rule
	}

	for i := range m.config.ASNRules {
		rule := &m.config.ASNRules[i]
		m.asnRulesMap[rule.ASN] = rule
	}

	return nil
}

// save writes the IP config to JSON file
func (m *IPManager) save() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Update last modified timestamp
	m.config.LastModified = time.Now()

	// Rebuild slices from maps
	m.config.BannedIPs = make([]IPRule, 0, len(m.bannedMap))
	for _, rule := range m.bannedMap {
		m.config.BannedIPs = append(m.config.BannedIPs, *rule)
	}

	m.config.WhitelistedIPs = make([]IPRule, 0, len(m.whitelistMap))
	for _, rule := range m.whitelistMap {
		m.config.WhitelistedIPs = append(m.config.WhitelistedIPs, *rule)
	}

	m.config.MonitoredIPs = make([]IPRule, 0, len(m.monitoredMap))
	for _, rule := range m.monitoredMap {
		m.config.MonitoredIPs = append(m.config.MonitoredIPs, *rule)
	}

	m.config.ChallengedIPs = make([]IPRule, 0, len(m.challengedMap))
	for _, rule := range m.challengedMap {
		m.config.ChallengedIPs = append(m.config.ChallengedIPs, *rule)
	}

	m.config.ThrottledIPs = make([]IPRule, 0, len(m.throttledMap))
	for _, rule := range m.throttledMap {
		m.config.ThrottledIPs = append(m.config.ThrottledIPs, *rule)
	}

	m.config.GeoRules = make([]GeoRule, 0, len(m.geoRulesMap))
	for _, rule := range m.geoRulesMap {
		m.config.GeoRules = append(m.config.GeoRules, *rule)
	}

	m.config.ASNRules = make([]ASNRule, 0, len(m.asnRulesMap))
	for _, rule := range m.asnRulesMap {
		m.config.ASNRules = append(m.config.ASNRules, *rule)
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal IP config: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(m.configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write to file
	if err := os.WriteFile(m.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write IP config: %w", err)
	}

	return nil
}

// Reload reloads the IP config from disk (useful for external edits)
func (m *IPManager) Reload() error {
	return m.load()
}

// BanIP adds an IP to the ban list with optional expiration
func (m *IPManager) BanIP(ip, reason, bannedBy string, duration time.Duration, tags []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove from whitelist if present
	delete(m.whitelistMap, ip)

	var expiresAt *time.Time
	if duration > 0 {
		expiry := time.Now().Add(duration)
		expiresAt = &expiry
	}

	rule := &IPRule{
		IP:        ip,
		Type:      "ban",
		Reason:    reason,
		BannedBy:  bannedBy,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		Tags:      tags,
		AutoBan:   false,
	}

	m.bannedMap[ip] = rule

	if m.autoSave {
		m.mu.Unlock()
		err := m.save()
		m.mu.Lock()
		return err
	}

	return nil
}

// UnbanIP removes an IP from the ban list
func (m *IPManager) UnbanIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.bannedMap, ip)

	if m.autoSave {
		m.mu.Unlock()
		err := m.save()
		m.mu.Lock()
		return err
	}

	return nil
}

// WhitelistIP adds an IP to the whitelist (immune to all DDoS checks)
func (m *IPManager) WhitelistIP(ip, reason, addedBy string, notes string, tags []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove from ban list if present
	delete(m.bannedMap, ip)

	rule := &IPRule{
		IP:        ip,
		Type:      "whitelist",
		Reason:    reason,
		BannedBy:  addedBy,
		CreatedAt: time.Now(),
		Notes:     notes,
		Tags:      tags,
	}

	m.whitelistMap[ip] = rule

	if m.autoSave {
		m.mu.Unlock()
		err := m.save()
		m.mu.Lock()
		return err
	}

	return nil
}

// UnwhitelistIP removes an IP from the whitelist
func (m *IPManager) UnwhitelistIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.whitelistMap, ip)

	if m.autoSave {
		m.mu.Unlock()
		err := m.save()
		m.mu.Lock()
		return err
	}

	return nil
}

// MonitorIP adds an IP to the monitoring list (logged with extra detail)
func (m *IPManager) MonitorIP(ip, reason string, tags []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rule := &IPRule{
		IP:        ip,
		Type:      "monitor",
		Reason:    reason,
		CreatedAt: time.Now(),
		Tags:      tags,
	}

	m.monitoredMap[ip] = rule

	if m.autoSave {
		m.mu.Unlock()
		err := m.save()
		m.mu.Lock()
		return err
	}

	return nil
}

// UnmonitorIP removes an IP from the monitoring list
func (m *IPManager) UnmonitorIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.monitoredMap, ip)

	if m.autoSave {
		m.mu.Unlock()
		err := m.save()
		m.mu.Lock()
		return err
	}

	return nil
}

// IsBanned checks if an IP is currently banned
func (m *IPManager) IsBanned(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rule, exists := m.bannedMap[ip]
	if !exists {
		return false
	}

	// Check if ban has expired
	if rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt) {
		return false
	}

	return true
}

// IsWhitelisted checks if an IP is whitelisted
func (m *IPManager) IsWhitelisted(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.whitelistMap[ip]
	return exists
}

// IsMonitored checks if an IP is being monitored
func (m *IPManager) IsMonitored(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.monitoredMap[ip]
	return exists
}

// GetIPRule returns the rule for a given IP (if any)
func (m *IPManager) GetIPRule(ip string) *IPRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if rule, exists := m.bannedMap[ip]; exists {
		return rule
	}
	if rule, exists := m.whitelistMap[ip]; exists {
		return rule
	}
	if rule, exists := m.monitoredMap[ip]; exists {
		return rule
	}

	return nil
}

// AddViolation adds a violation log entry to an IP rule
func (m *IPManager) AddViolation(ip, violation string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if rule, exists := m.bannedMap[ip]; exists {
		timestamp := time.Now().Format(time.RFC3339)
		rule.ViolationLog = append(rule.ViolationLog, fmt.Sprintf("[%s] %s", timestamp, violation))
	}
}

// AutoBanIP creates an automatic ban (triggered by DDoS detection)
func (m *IPManager) AutoBanIP(ip, reason string, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Don't auto-ban whitelisted IPs
	if _, exists := m.whitelistMap[ip]; exists {
		return nil
	}

	var expiresAt *time.Time
	if duration > 0 {
		expiry := time.Now().Add(duration)
		expiresAt = &expiry
	}

	rule := &IPRule{
		IP:        ip,
		Type:      "ban",
		Reason:    reason,
		BannedBy:  "auto-ddos-detection",
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		Tags:      []string{"auto-ban"},
		AutoBan:   true,
	}

	m.bannedMap[ip] = rule

	// Don't auto-save for automatic bans (too frequent)
	return nil
}

// cleanupExpiredRules periodically removes expired bans
func (m *IPManager) cleanupExpiredRules() {
	for range m.cleanupTimer.C {
		m.mu.Lock()

		now := time.Now()
		removed := 0

		// Check all banned IPs for expiration
		for ip, rule := range m.bannedMap {
			if rule.ExpiresAt != nil && now.After(*rule.ExpiresAt) {
				delete(m.bannedMap, ip)
				removed++
			}
		}

		m.mu.Unlock()

		if removed > 0 {
			log.Printf("IP Manager: Cleaned up %d expired bans", removed)
			if m.autoSave {
				m.save()
			}
		}
	}
}

// GetStats returns statistics about IP management
func (m *IPManager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	permanentBans := 0
	temporaryBans := 0
	autoBans := 0

	for _, rule := range m.bannedMap {
		if rule.ExpiresAt == nil {
			permanentBans++
		} else {
			temporaryBans++
		}
		if rule.AutoBan {
			autoBans++
		}
	}

	return map[string]interface{}{
		"total_banned":   len(m.bannedMap),
		"permanent_bans": permanentBans,
		"temporary_bans": temporaryBans,
		"auto_bans":      autoBans,
		"whitelisted":    len(m.whitelistMap),
		"monitored":      len(m.monitoredMap),
		"config_path":    m.configPath,
		"last_modified":  m.config.LastModified,
	}
}

// ListBannedIPs returns all currently banned IPs
func (m *IPManager) ListBannedIPs() []IPRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rules := make([]IPRule, 0, len(m.bannedMap))
	for _, rule := range m.bannedMap {
		rules = append(rules, *rule)
	}

	return rules
}

// ListWhitelistedIPs returns all whitelisted IPs
func (m *IPManager) ListWhitelistedIPs() []IPRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rules := make([]IPRule, 0, len(m.whitelistMap))
	for _, rule := range m.whitelistMap {
		rules = append(rules, *rule)
	}

	return rules
}

// ListMonitoredIPs returns all monitored IPs
func (m *IPManager) ListMonitoredIPs() []IPRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rules := make([]IPRule, 0, len(m.monitoredMap))
	for _, rule := range m.monitoredMap {
		rules = append(rules, *rule)
	}

	return rules
}

// ExportConfig exports the current config to a specific file
func (m *IPManager) ExportConfig(path string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// AddGeoRule adds a geolocation-based rule
func (m *IPManager) AddGeoRule(countryCode, action, reason string, throttlePercent int, expiresIn time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var expiresAt *time.Time
	if expiresIn > 0 {
		expiry := time.Now().Add(expiresIn)
		expiresAt = &expiry
	}

	rule := &GeoRule{
		CountryCode:     countryCode,
		Action:          action,
		Reason:          reason,
		CreatedAt:       time.Now(),
		ExpiresAt:       expiresAt,
		ThrottlePercent: throttlePercent,
	}

	m.geoRulesMap[countryCode] = rule

	if m.autoSave {
		m.mu.Unlock()
		err := m.save()
		m.mu.Lock()
		return err
	}

	return nil
}

// RemoveGeoRule removes a geolocation rule
func (m *IPManager) RemoveGeoRule(countryCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.geoRulesMap, countryCode)

	if m.autoSave {
		m.mu.Unlock()
		err := m.save()
		m.mu.Lock()
		return err
	}

	return nil
}

// GetGeoRule returns the rule for a country code
func (m *IPManager) GetGeoRule(countryCode string) *GeoRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if rule, exists := m.geoRulesMap[countryCode]; exists {
		// Check expiration
		if rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt) {
			return nil
		}
		return rule
	}

	return nil
}

// CheckGeoAccess determines if a country is allowed/blocked
func (m *IPManager) CheckGeoAccess(countryCode string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check specific geo rule first
	if rule, exists := m.geoRulesMap[countryCode]; exists {
		if rule.ExpiresAt == nil || time.Now().Before(*rule.ExpiresAt) {
			return rule.Action
		}
	}

	// Check global allowed countries (whitelist mode)
	if len(m.config.GlobalRules.AllowedCountries) > 0 {
		for _, allowed := range m.config.GlobalRules.AllowedCountries {
			if allowed == countryCode {
				return "allow"
			}
		}
		return "block" // Not in allowed list
	}

	// Check global blocked countries
	for _, blocked := range m.config.GlobalRules.BlockedCountries {
		if blocked == countryCode {
			return "block"
		}
	}

	// Check challenge countries
	for _, challenge := range m.config.GlobalRules.ChallengeCountries {
		if challenge == countryCode {
			return "challenge"
		}
	}

	// Check require auth countries
	for _, authRequired := range m.config.GlobalRules.RequireAuthCountries {
		if authRequired == countryCode {
			return "require_auth"
		}
	}

	return m.config.GlobalRules.DefaultAction
}

// ThrottleIP adds an IP to throttled list
func (m *IPManager) ThrottleIP(ip, reason string, throttlePercent int, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var expiresAt *time.Time
	if duration > 0 {
		expiry := time.Now().Add(duration)
		expiresAt = &expiry
	}

	rule := &IPRule{
		IP:              ip,
		Type:            "throttle",
		Reason:          reason,
		CreatedAt:       time.Now(),
		ExpiresAt:       expiresAt,
		ThrottlePercent: throttlePercent,
	}

	m.throttledMap[ip] = rule

	if m.autoSave {
		m.mu.Unlock()
		err := m.save()
		m.mu.Lock()
		return err
	}

	return nil
}

// IsThrottled checks if an IP is throttled and returns the throttle percentage
func (m *IPManager) IsThrottled(ip string) (bool, int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rule, exists := m.throttledMap[ip]
	if !exists {
		return false, 0
	}

	if rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt) {
		return false, 0
	}

	return true, rule.ThrottlePercent
}

// GetIPRuleByIP returns the most specific rule for an IP (prioritized)
func (m *IPManager) GetIPRuleByIP(ip string) *IPRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Priority order: whitelist > ban > throttle > challenge > monitor
	if rule, exists := m.whitelistMap[ip]; exists {
		return rule
	}
	if rule, exists := m.bannedMap[ip]; exists {
		return rule
	}
	if rule, exists := m.throttledMap[ip]; exists {
		return rule
	}
	if rule, exists := m.challengedMap[ip]; exists {
		return rule
	}
	if rule, exists := m.monitoredMap[ip]; exists {
		return rule
	}

	return nil
}

// UpdateGlobalRules updates the global WAF policies
func (m *IPManager) UpdateGlobalRules(rules GlobalRules) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config.GlobalRules = rules

	if m.autoSave {
		m.mu.Unlock()
		err := m.save()
		m.mu.Lock()
		return err
	}

	return nil
}

// GetGlobalRules returns the current global rules
func (m *IPManager) GetGlobalRules() GlobalRules {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.GlobalRules
}

// Close stops the cleanup timer and saves any pending changes
func (m *IPManager) Close() error {
	if m.cleanupTimer != nil {
		m.cleanupTimer.Stop()
	}

	if m.autoSave {
		return m.save()
	}

	return nil
}

// RequestContext contains information about an incoming request for validation
type RequestContext struct {
	IP            string
	Path          string
	Method        string
	UserAgent     string
	Referer       string
	Headers       map[string]string
	Cookies       map[string]string
	QueryParams   map[string]string
	ContentType   string
	ContentLength int64
	Protocol      string
	TLSVersion    string
	Port          int
	IsHTTPS       bool
	Timestamp     time.Time
}

// ValidateRequest performs comprehensive request validation against IP rules
func (m *IPManager) ValidateRequest(ctx *RequestContext) (allowed bool, reason string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rule := m.GetIPRuleByIP(ctx.IP)
	if rule == nil {
		return true, ""
	}

	// Whitelist override
	if rule.Type == "whitelist" && rule.WhitelistOverride {
		return true, "whitelisted"
	}

	// Check time-based restrictions
	if !m.checkTimeRestrictions(rule, ctx.Timestamp) {
		return false, "time_restricted"
	}

	// Check path restrictions
	if !m.checkPathRestrictions(rule, ctx.Path) {
		return false, "path_blocked"
	}

	// Check method restrictions
	if !m.checkMethodRestrictions(rule, ctx.Method) {
		return false, "method_blocked"
	}

	// Check user agent restrictions
	if !m.checkUserAgentRestrictions(rule, ctx.UserAgent) {
		return false, "user_agent_blocked"
	}

	// Check referer restrictions
	if !m.checkRefererRestrictions(rule, ctx.Referer) {
		return false, "referer_blocked"
	}

	// Check header requirements
	if !m.checkHeaderRequirements(rule, ctx.Headers) {
		return false, "missing_required_headers"
	}

	// Check cookie requirements
	if !m.checkCookieRequirements(rule, ctx.Cookies) {
		return false, "missing_required_cookies"
	}

	// Check content type restrictions
	if !m.checkContentTypeRestrictions(rule, ctx.ContentType) {
		return false, "content_type_blocked"
	}

	// Check size limits
	if !m.checkSizeLimits(rule, ctx) {
		return false, "size_limit_exceeded"
	}

	// Check protocol requirements
	if !m.checkProtocolRequirements(rule, ctx) {
		return false, "protocol_requirement_failed"
	}

	return true, ""
}

func (m *IPManager) checkTimeRestrictions(rule *IPRule, timestamp time.Time) bool {
	if len(rule.AllowedHours) > 0 {
		hour := timestamp.Hour()
		allowed := false
		for _, h := range rule.AllowedHours {
			if h == hour {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	if len(rule.BlockedHours) > 0 {
		hour := timestamp.Hour()
		for _, h := range rule.BlockedHours {
			if h == hour {
				return false
			}
		}
	}

	if len(rule.AllowedDays) > 0 {
		day := timestamp.Weekday().String()[:3]
		allowed := false
		for _, d := range rule.AllowedDays {
			if d == day {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	if len(rule.BlockedDays) > 0 {
		day := timestamp.Weekday().String()[:3]
		for _, d := range rule.BlockedDays {
			if d == day {
				return false
			}
		}
	}

	return true
}

func (m *IPManager) checkPathRestrictions(rule *IPRule, path string) bool {
	if len(rule.AllowedPaths) > 0 {
		allowed := false
		for _, allowedPath := range rule.AllowedPaths {
			if matchPattern(path, allowedPath) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	if len(rule.BlockedPaths) > 0 {
		for _, blockedPath := range rule.BlockedPaths {
			if matchPattern(path, blockedPath) {
				return false
			}
		}
	}

	return true
}

func (m *IPManager) checkMethodRestrictions(rule *IPRule, method string) bool {
	if len(rule.AllowedMethods) > 0 {
		allowed := false
		for _, allowedMethod := range rule.AllowedMethods {
			if allowedMethod == method {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	if len(rule.BlockedMethods) > 0 {
		for _, blockedMethod := range rule.BlockedMethods {
			if blockedMethod == method {
				return false
			}
		}
	}

	return true
}

func (m *IPManager) checkUserAgentRestrictions(rule *IPRule, userAgent string) bool {
	if len(rule.AllowedUserAgents) > 0 {
		allowed := false
		for _, pattern := range rule.AllowedUserAgents {
			if matchPattern(userAgent, pattern) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	if len(rule.BlockedUserAgents) > 0 {
		for _, pattern := range rule.BlockedUserAgents {
			if matchPattern(userAgent, pattern) {
				return false
			}
		}
	}

	if rule.BlockHeadless && isHeadlessBrowser(userAgent) {
		return false
	}

	if rule.BlockBots && isBotUserAgent(userAgent) {
		return false
	}

	return true
}

func (m *IPManager) checkRefererRestrictions(rule *IPRule, referer string) bool {
	if len(rule.AllowedReferers) > 0 {
		if referer == "" {
			return false
		}
		allowed := false
		for _, pattern := range rule.AllowedReferers {
			if matchPattern(referer, pattern) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	if len(rule.BlockedReferers) > 0 {
		for _, pattern := range rule.BlockedReferers {
			if matchPattern(referer, pattern) {
				return false
			}
		}
	}

	return true
}

func (m *IPManager) checkHeaderRequirements(rule *IPRule, headers map[string]string) bool {
	for _, required := range rule.RequiredHeaders {
		if _, exists := headers[required]; !exists {
			return false
		}
	}

	for _, blocked := range rule.BlockedHeaders {
		if _, exists := headers[blocked]; exists {
			return false
		}
	}

	return true
}

func (m *IPManager) checkCookieRequirements(rule *IPRule, cookies map[string]string) bool {
	for _, required := range rule.RequireCookies {
		if _, exists := cookies[required]; !exists {
			return false
		}
	}
	return true
}

func (m *IPManager) checkContentTypeRestrictions(rule *IPRule, contentType string) bool {
	if len(rule.AllowedContentTypes) > 0 {
		allowed := false
		for _, ct := range rule.AllowedContentTypes {
			if matchPattern(contentType, ct) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	if len(rule.BlockedContentTypes) > 0 {
		for _, ct := range rule.BlockedContentTypes {
			if matchPattern(contentType, ct) {
				return false
			}
		}
	}

	return true
}

func (m *IPManager) checkSizeLimits(rule *IPRule, ctx *RequestContext) bool {
	if rule.MaxUploadSize > 0 && ctx.ContentLength > rule.MaxUploadSize {
		return false
	}

	if rule.MaxURLLength > 0 && len(ctx.Path) > rule.MaxURLLength {
		return false
	}

	if rule.MaxHeaderSize > 0 {
		totalSize := 0
		for k, v := range ctx.Headers {
			totalSize += len(k) + len(v)
		}
		if totalSize > rule.MaxHeaderSize {
			return false
		}
	}

	return true
}

func (m *IPManager) checkProtocolRequirements(rule *IPRule, ctx *RequestContext) bool {
	if rule.RequireHTTPS && !ctx.IsHTTPS {
		return false
	}

	if rule.RequireHTTP2 && ctx.Protocol != "HTTP/2" && ctx.Protocol != "HTTP/2.0" {
		return false
	}

	if len(rule.BlockedProtocols) > 0 {
		for _, blocked := range rule.BlockedProtocols {
			if ctx.Protocol == blocked {
				return false
			}
		}
	}

	if len(rule.AllowedPorts) > 0 {
		allowed := false
		for _, port := range rule.AllowedPorts {
			if port == ctx.Port {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	if len(rule.BlockedPorts) > 0 {
		for _, port := range rule.BlockedPorts {
			if port == ctx.Port {
				return false
			}
		}
	}

	return true
}

// Helper functions
func matchPattern(text, pattern string) bool {
	// Simple wildcard matching (* for any chars)
	if pattern == "*" {
		return true
	}
	if len(pattern) == 0 {
		return len(text) == 0
	}
	// Simple contains check for now
	if pattern[0] == '*' && pattern[len(pattern)-1] == '*' {
		return len(text) >= len(pattern)-2
	}
	if pattern[0] == '*' {
		suffix := pattern[1:]
		return len(text) >= len(suffix) && text[len(text)-len(suffix):] == suffix
	}
	if pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(text) >= len(prefix) && text[:len(prefix)] == prefix
	}
	return text == pattern
}

func isHeadlessBrowser(ua string) bool {
	headlessPatterns := []string{"HeadlessChrome", "PhantomJS", "Puppeteer", "Selenium"}
	for _, pattern := range headlessPatterns {
		if matchPattern(ua, "*"+pattern+"*") {
			return true
		}
	}
	return false
}

func isBotUserAgent(ua string) bool {
	botPatterns := []string{"bot", "crawler", "spider", "scraper", "curl", "wget"}
	uaLower := ""
	for _, c := range ua {
		if c >= 'A' && c <= 'Z' {
			uaLower += string(c + 32)
		} else {
			uaLower += string(c)
		}
	}
	for _, pattern := range botPatterns {
		if matchPattern(uaLower, "*"+pattern+"*") {
			return true
		}
	}
	return false
}
