// Package config loads the app-level runtime config from features.json.
//
// This only covers the middleware that cmd/rhinowaf owns: the listen address,
// the fallback backend, challenge, fingerprint, websocket and logging. IP,
// geo, rate limit and smuggling rules live in config/ip_rules.json and are
// loaded separately, so we deliberately do not model them here. If a field is
// in this struct it actually does something, so the file never lies about what
// it controls.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// Config is the parsed features.json. Every section maps to real wiring in
// cmd/rhinowaf/main.go. Missing sections fall back to Default().
type Config struct {
	Version     string            `json:"version"`
	Server      ServerConfig      `json:"server"`
	Backend     BackendConfig     `json:"backend"`
	Challenge   ChallengeConfig   `json:"challenge_system"`
	Fingerprint FingerprintConfig `json:"fingerprinting"`
	WebSocket   WebSocketConfig   `json:"websocket"`
	Logging     LoggingConfig     `json:"logging"`
}

type ServerConfig struct {
	Listen string `json:"listen"`
	// timeouts guard the WAF's own listener against slow-client (slowloris)
	// attacks. seconds. 0 means "use the built-in default".
	ReadHeaderTimeoutSeconds int `json:"read_header_timeout_seconds"`
	ReadTimeoutSeconds       int `json:"read_timeout_seconds"`
	WriteTimeoutSeconds      int `json:"write_timeout_seconds"`
	IdleTimeoutSeconds       int `json:"idle_timeout_seconds"`
	MaxHeaderBytes           int `json:"max_header_bytes"`
}

type BackendConfig struct {
	ProxyURL       string `json:"proxy_url"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	MaxIdleConns   int    `json:"max_idle_conns"`
}

type ChallengeConfig struct {
	Enabled         bool     `json:"enabled"`
	DefaultType     string   `json:"default_type"` // javascript | proof_of_work | hcaptcha | turnstile
	PowDifficulty   int      `json:"pow_difficulty"`
	WhitelistPaths  []string `json:"whitelist_paths"`
	RequireForPaths []string `json:"require_for_paths"`
}

type FingerprintConfig struct {
	Enabled              bool `json:"enabled"`
	MaxIPsPerFingerprint int  `json:"max_ips_per_fingerprint"`
	SuspiciousThreshold  int  `json:"suspicious_threshold"`
	MaxAgeHours          int  `json:"max_age_hours"`
	BlockOnExceed        bool `json:"block_on_exceed"`
	RequireClientData    bool `json:"require_client_data"`
	CollectionRateLimit  int  `json:"collection_rate_limit"`
}

type WebSocketConfig struct {
	Enabled                     bool     `json:"enabled"`
	MaxConnectionsPerIP         int      `json:"max_connections_per_ip"`
	ConnectionRateLimit         int      `json:"connection_rate_limit"`
	ConnectionRateWindowSeconds int      `json:"connection_rate_window_seconds"`
	MaxMessageSize              int64    `json:"max_message_size"`
	MessageRateLimit            int      `json:"message_rate_limit"`
	MessageRateWindowSeconds    int      `json:"message_rate_window_seconds"`
	AllowedOrigins              []string `json:"allowed_origins"`
	AllowOriginWildcard         bool     `json:"allow_origin_wildcard"`
	BlockBinaryMessages         bool     `json:"block_binary_messages"`
	MaxViolations               int      `json:"max_violations"`
	ViolationBanDurationMinutes int      `json:"violation_ban_duration_minutes"`
	IdleTimeoutMinutes          int      `json:"idle_timeout_minutes"`
	HandshakeTimeoutSeconds     int      `json:"handshake_timeout_seconds"`
}

type LoggingConfig struct {
	Enabled    bool `json:"enabled"`
	MaxSizeMB  int  `json:"max_size_mb"`
	MaxAgeDays int  `json:"max_age_days"`
	MaxBackups int  `json:"max_backups"`
	Compress   bool `json:"compress"`
}

// Default returns the built-in config. These values match what RhinoWAF used
// when everything was hardcoded, so a missing features.json behaves exactly
// like older builds.
func Default() *Config {
	return &Config{
		Version: "1.0.5",
		Server: ServerConfig{
			Listen:                   ":8080",
			ReadHeaderTimeoutSeconds: 10,
			ReadTimeoutSeconds:       30,
			WriteTimeoutSeconds:      60,
			IdleTimeoutSeconds:       120,
			MaxHeaderBytes:           1 << 20, // 1 MiB
		},
		Backend: BackendConfig{
			ProxyURL:       "http://localhost:9000",
			TimeoutSeconds: 30,
			MaxIdleConns:   100,
		},
		Challenge: ChallengeConfig{
			Enabled:         true,
			DefaultType:     "javascript",
			PowDifficulty:   5,
			WhitelistPaths:  []string{"/challenge/"},
			RequireForPaths: []string{},
		},
		Fingerprint: FingerprintConfig{
			Enabled:              true,
			MaxIPsPerFingerprint: 5,
			SuspiciousThreshold:  3,
			MaxAgeHours:          24,
			BlockOnExceed:        false,
			RequireClientData:    false,
			CollectionRateLimit:  60,
		},
		WebSocket: WebSocketConfig{
			Enabled:                     true,
			MaxConnectionsPerIP:         10,
			ConnectionRateLimit:         5,
			ConnectionRateWindowSeconds: 60,
			MaxMessageSize:              1024 * 1024,
			MessageRateLimit:            100,
			MessageRateWindowSeconds:    60,
			AllowedOrigins:              []string{},
			AllowOriginWildcard:         true,
			BlockBinaryMessages:         false,
			MaxViolations:               5,
			ViolationBanDurationMinutes: 30,
			IdleTimeoutMinutes:          5,
			HandshakeTimeoutSeconds:     10,
		},
		Logging: LoggingConfig{
			Enabled:    true,
			MaxSizeMB:  100,
			MaxAgeDays: 30,
			MaxBackups: 3,
			Compress:   true,
		},
	}
}

// Load reads features.json from path and overlays it on the defaults. If the
// file does not exist, defaults are returned with no error (that is the normal
// "just run it" path). A file that exists but is malformed or invalid is a
// hard error so a typo never silently drops your protection.
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// tolerate a UTF-8 BOM some editors prepend, then decode straight onto the
	// defaults so any section the user leaves out keeps its default value
	// instead of going to a zero value.
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Server.Listen == "" {
		return fmt.Errorf("server.listen must not be empty")
	}
	switch c.Challenge.DefaultType {
	case "javascript", "proof_of_work", "hcaptcha", "turnstile":
	default:
		return fmt.Errorf("challenge_system.default_type %q is not one of javascript, proof_of_work, hcaptcha, turnstile", c.Challenge.DefaultType)
	}
	if c.Challenge.PowDifficulty < 1 || c.Challenge.PowDifficulty > 8 {
		return fmt.Errorf("challenge_system.pow_difficulty %d out of range 1-8", c.Challenge.PowDifficulty)
	}
	if c.Backend.ProxyURL == "" {
		return fmt.Errorf("backend.proxy_url must not be empty")
	}
	if c.Fingerprint.MaxIPsPerFingerprint < 1 {
		return fmt.Errorf("fingerprinting.max_ips_per_fingerprint must be >= 1")
	}
	if c.WebSocket.MaxMessageSize < 0 {
		return fmt.Errorf("websocket.max_message_size must be >= 0")
	}
	return nil
}
