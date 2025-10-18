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
	Type         string     `json:"type"` // "ban", "whitelist", "monitor"
	Reason       string     `json:"reason"`
	BannedBy     string     `json:"banned_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"` // nil = permanent
	ViolationLog []string   `json:"violation_log,omitempty"`
	Notes        string     `json:"notes,omitempty"`
	Tags         []string   `json:"tags,omitempty"`
	AutoBan      bool       `json:"auto_ban"` // If true, this was an automatic ban
}

// IPConfig represents the JSON configuration file for IP management
type IPConfig struct {
	Version        string    `json:"version"`
	LastModified   time.Time `json:"last_modified"`
	BannedIPs      []IPRule  `json:"banned_ips"`
	WhitelistedIPs []IPRule  `json:"whitelisted_ips"`
	MonitoredIPs   []IPRule  `json:"monitored_ips"` // IPs to watch closely
}

// IPManager handles loading, saving, and querying IP management rules
type IPManager struct {
	mu           sync.RWMutex
	configPath   string
	config       *IPConfig
	bannedMap    map[string]*IPRule
	whitelistMap map[string]*IPRule
	monitoredMap map[string]*IPRule
	autoSave     bool
	cleanupTimer *time.Ticker
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
			configPath:   configPath,
			bannedMap:    make(map[string]*IPRule),
			whitelistMap: make(map[string]*IPRule),
			monitoredMap: make(map[string]*IPRule),
			autoSave:     autoSave,
			cleanupTimer: time.NewTicker(1 * time.Hour),
		}

		// Try to load existing config
		if err := ipManager.load(); err != nil {
			// If file doesn't exist, create a new config
			if os.IsNotExist(err) {
				ipManager.config = &IPConfig{
					Version:        "1.0",
					LastModified:   time.Now(),
					BannedIPs:      []IPRule{},
					WhitelistedIPs: []IPRule{},
					MonitoredIPs:   []IPRule{},
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

		log.Printf("IP Manager initialized: %d banned, %d whitelisted, %d monitored",
			len(ipManager.bannedMap), len(ipManager.whitelistMap), len(ipManager.monitoredMap))
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
