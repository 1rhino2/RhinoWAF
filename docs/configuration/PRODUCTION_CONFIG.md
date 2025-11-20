# RhinoWAF Production Configuration Guide

**Version 2.0** | Last Updated: October 21, 2025 OUTDATED

This guide covers complete production configuration for RhinoWAF, including security modes, CAPTCHA integration, and deployment best practices.

## Table of Contents

- [Quick Start](#quick-start)
- [Security Modes](#security-modes)
- [Configuration Files](#configuration-files)
- [Challenge System](#challenge-system)
- [Browser Fingerprinting](#browser-fingerprinting)
- [IP Rules & Geolocation](#ip-rules--geolocation)
- [Rate Limiting](#rate-limiting)
- [Production Checklist](#production-checklist)

---

## Quick Start

### Default Configuration (Production-Ready)

RhinoWAF ships with **production-ready defaults** that work out of the box:

```bash
# Build
go build -o rhinowaf ./cmd/rhinowaf

# Run
./rhinowaf
```

**What's Enabled by Default:**
-  Challenge System (JavaScript challenges)
-  Browser Fingerprinting (bot network detection)
-  Geolocation Blocking (CN, RU challenged; KP blocked)
-  Proxy/Tor Blocking
-  Rate Limiting (100 req/IP, 10 concurrent connections)
-  User-Agent Filtering (blocks empty/suspicious UAs)

---

## Security Modes

RhinoWAF supports multiple security profiles depending on your threat model.

### Mode 1: Testing/Development

**Use Case:** Local development, CI/CD, API testing

**Configuration** (`cmd/rhinowaf/main.go`):

```go
// Challenge System
challengeConfig := challenge.Config{
    Enabled:         false,  // Disable challenges for testing
    DefaultType:     challenge.TypeJavaScript,
    Difficulty:      3,
    WhitelistPaths:  []string{"/"},
}

// Fingerprinting
fingerprintConfig := fingerprint.Config{
    Enabled:              false,  // Disable fingerprinting
    MaxIPsPerFingerprint: 5,
    BlockOnExceed:        false,
    RequireClientData:    false,
}
```

**Global Rules** (`config/ip_rules.json`):

```json
{
  "global_rules": {
    "default_action": "allow",
    "block_proxies": false,
    "block_tor": false,
    "block_hosting": false,
    "max_requests_per_ip": 1000,
    "max_connections_per_ip": 50,
    "block_empty_user_agent": false,
    "block_suspicious_ua": false
  }
}
```

### Mode 2: Standard Web Application (Default)

**Use Case:** Most public-facing websites, APIs, e-commerce

**Configuration** (`cmd/rhinowaf/main.go`):

```go
// Challenge System - Basic JavaScript
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeJavaScript,
    Difficulty:      5,
    WhitelistPaths:  []string{"/static/", "/health"},
    RequireForPaths: []string{},  // Empty = challenge on suspicious behavior only
}

// Fingerprinting - Active bot detection
fingerprintConfig := fingerprint.Config{
    Enabled:              true,
    MaxIPsPerFingerprint: 5,
    MaxAgeForReuse:       24 * time.Hour,
    SuspiciousThreshold:  3,
    BlockOnExceed:        true,   // Block when limits exceeded
    RequireClientData:    true,   // Require canvas/WebGL data
}
```

**Global Rules** (`config/ip_rules.json`):

```json
{
  "global_rules": {
    "default_action": "allow",
    "block_proxies": true,
    "block_tor": true,
    "block_hosting": true,
    "max_requests_per_ip": 100,
    "max_connections_per_ip": 10,
    "block_empty_user_agent": true,
    "block_suspicious_ua": true
  }
}
```

### Mode 3: High-Security (Banking, Healthcare, Government)

**Use Case:** Sensitive data, compliance requirements, high-value targets

**Configuration** (`cmd/rhinowaf/main.go`):

```go
// Challenge System - hCaptcha for all sensitive paths
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeHCaptcha,  // Requires API keys
    Difficulty:      6,  // Max difficulty for proof-of-work fallback
    WhitelistPaths:  []string{},  // No whitelist
    RequireForPaths: []string{"/login", "/register", "/api/", "/admin/"},
}

// Fingerprinting - Strict bot detection
fingerprintConfig := fingerprint.Config{
    Enabled:              true,
    MaxIPsPerFingerprint: 3,     // Stricter limit
    MaxAgeForReuse:       12 * time.Hour,  // Shorter reuse window
    SuspiciousThreshold:  2,     // More sensitive
    BlockOnExceed:        true,
    RequireClientData:    true,
}
```

**Global Rules** (`config/ip_rules.json`):

```json
{
  "global_rules": {
    "default_action": "challenge",  // Challenge by default
    "block_proxies": true,
    "block_tor": true,
    "block_hosting": true,
    "max_requests_per_ip": 50,
    "max_connections_per_ip": 5,
    "block_empty_user_agent": true,
    "block_suspicious_ua": true
  },
  "geo_rules": [
    {
      "country_code": "CN",
      "action": "block"  // Block instead of challenge
    },
    {
      "country_code": "RU",
      "action": "block"
    },
    {
      "country_code": "KP",
      "action": "block"
    }
  ]
}
```

### Mode 4: Under Active Attack

**Use Case:** DDoS mitigation, credential stuffing defense

**Configuration** (`cmd/rhinowaf/main.go`):

```go
// Challenge System - Expensive proof-of-work
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeProofOfWork,
    Difficulty:      6,  // 10-30 seconds per solve
    WhitelistPaths:  []string{},
    RequireForPaths: []string{"/"},  // Protect entire site
}

// Fingerprinting - Maximum strictness
fingerprintConfig := fingerprint.Config{
    Enabled:              true,
    MaxIPsPerFingerprint: 1,     // No IP sharing allowed
    MaxAgeForReuse:       6 * time.Hour,
    SuspiciousThreshold:  1,
    BlockOnExceed:        true,
    RequireClientData:    true,
}
```

**Global Rules** (`config/ip_rules.json`):

```json
{
  "global_rules": {
    "default_action": "challenge",
    "block_proxies": true,
    "block_tor": true,
    "block_hosting": true,
    "max_requests_per_ip": 20,      // Very restrictive
    "max_connections_per_ip": 2,
    "block_empty_user_agent": true,
    "block_suspicious_ua": true
  }
}
```

---

## Configuration Files

### Main Configuration (`cmd/rhinowaf/main.go`)

This file controls application-level settings:

**Key Sections:**

```go
// 1. Fingerprint Configuration (Lines 42-51)
fingerprintConfig := fingerprint.Config{
    Enabled:              true,   // Toggle fingerprinting on/off
    MaxIPsPerFingerprint: 5,      // Bot network threshold
    MaxAgeForReuse:       24 * time.Hour,
    SuspiciousThreshold:  3,      // Flag when 3+ IPs share fingerprint
    BlockOnExceed:        true,   // Block when MaxIPsPerFingerprint exceeded
    RequireClientData:    true,   // Require canvas/WebGL (blocks headless)
}

// 2. Challenge Configuration (Lines 55-61)
challengeConfig := waf.ChallengeConfig{
    Enabled:    true,             // Toggle challenge system on/off
    Difficulty: 5,                // Proof-of-work difficulty (1-6)
    Timeout:    30 * time.Second, // Challenge timeout
}

// 3. Rate Limiting (waf/adaptive.go)
rateLimiter := ddos.NewRateLimiter(
    100,              // Max requests per IP
    time.Minute,      // Time window
    10,               // Max concurrent connections
)
```

**How to Modify:**

1. Edit `cmd/rhinowaf/main.go`
2. Change desired values
3. Rebuild: `go build -o rhinowaf ./cmd/rhinowaf`
4. Restart WAF: `./rhinowaf`

### IP Rules Configuration (`config/ip_rules.json`)

Controls IP-level and geolocation policies.

**Structure:**

```json
{
  "version": "2.0",
  "last_modified": "2025-10-21T00:00:00Z",
  "banned_ips": [
    {
      "ip": "203.0.113.42",
      "type": "ban",
      "reason": "Brute force attack",
      "created_at": "2025-10-21T12:00:00Z"
    }
  ],
  "whitelisted_ips": [
    {
      "ip": "10.0.0.1",
      "type": "whitelist",
      "reason": "Internal admin",
      "whitelist_override": true
    }
  ],
  "monitored_ips": [
    {
      "ip": "198.51.100.50",
      "type": "monitored",
      "reason": "Suspicious activity",
      "allowed_paths": ["/api/*"],
      "blocked_paths": ["/admin/*"],
      "blocked_methods": ["DELETE", "PUT"],
      "max_upload_size": 10485760,
      "max_url_length": 2048,
      "min_request_interval": 1
    }
  ],
  "geo_rules": [
    {
      "country_code": "CN",
      "action": "challenge",
      "throttle_percent": 40,
      "reason": "High-risk region"
    }
  ],
  "global_rules": {
    "default_action": "allow",
    "block_proxies": true,
    "block_tor": true,
    "block_hosting": true,
    "max_requests_per_ip": 100,
    "max_connections_per_ip": 10,
    "block_empty_user_agent": true,
    "block_suspicious_ua": true
  }
}
```

**Hot Reload:** Configuration changes require WAF restart (hot reload planned for v2.1).

---

## Challenge System

### Challenge Types

#### 1. JavaScript Challenge (Default)

**Best For:** Standard websites, low friction

**Configuration:**

```go
challengeConfig := challenge.Config{
    Enabled:     true,
    DefaultType: challenge.TypeJavaScript,
}
```

**How It Works:**
- 2-second delay + JS execution requirement
- Blocks curl, wget, simple bots
- No external dependencies
- Minimal user friction

#### 2. Proof-of-Work

**Best For:** DDoS attacks, making attacks expensive

**Configuration:**

```go
challengeConfig := challenge.Config{
    Enabled:     true,
    DefaultType: challenge.TypeProofOfWork,
    Difficulty:  5,  // 1-6: affects solve time
}
```

**Difficulty Levels:**
- 1-2: ~1 second (easy)
- 3-4: ~5 seconds (medium)
- 5-6: ~10-30 seconds (hard)

**How It Works:**
- Client-side SHA-256 computation
- Expensive for attackers (can't parallelize)
- No CAPTCHA solving required
- Works offline

#### 3. hCaptcha

**Best For:** Compliance (GDPR), privacy-focused

**Configuration:**

```bash
# Set environment variables
export HCAPTCHA_SITE_KEY="your-site-key"
export HCAPTCHA_SECRET="your-secret"
```

```go
challengeConfig := challenge.Config{
    Enabled:     true,
    DefaultType: challenge.TypeHCaptcha,
}
```

**Benefits:**
- 99% bot blocking
- GDPR compliant
- Privacy-focused
- Free tier available

**Get Keys:** https://hcaptcha.com

#### 4. Cloudflare Turnstile

**Best For:** Best user experience, invisible challenges

**Configuration:**

```bash
# Set environment variables
export TURNSTILE_SITE_KEY="your-site-key"
export TURNSTILE_SECRET="your-secret"
```

```go
challengeConfig := challenge.Config{
    Enabled:     true,
    DefaultType: challenge.TypeTurnstile,
}
```

**Benefits:**
- 95% bot blocking
- Invisible to most users
- Free
- Best UX

**Get Keys:** Cloudflare Dashboard → Turnstile

### Path-Specific Challenges

Require challenges for sensitive paths:

```go
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeHCaptcha,
    WhitelistPaths:  []string{"/static/", "/health"},  // Never challenge
    RequireForPaths: []string{"/login", "/api/"},       // Always challenge
}
```

---

## Browser Fingerprinting

### Configuration Options

```go
fingerprintConfig := fingerprint.Config{
    Enabled:              true,   // Toggle on/off
    MaxIPsPerFingerprint: 5,      // Bot network threshold
    MaxAgeForReuse:       24 * time.Hour,  // Fingerprint expiry
    SuspiciousThreshold:  3,      // Flag as suspicious
    BlockOnExceed:        true,   // Block when limit exceeded
    RequireClientData:    true,   // Require canvas/WebGL
}
```

**Parameters Explained:**

- **Enabled:** Master switch for fingerprinting
- **MaxIPsPerFingerprint:** Maximum IPs allowed per fingerprint (detects bot networks)
- **MaxAgeForReuse:** How long fingerprints are valid
- **SuspiciousThreshold:** Flag fingerprint as suspicious when this many IPs share it
- **BlockOnExceed:** Block IPs when MaxIPsPerFingerprint exceeded (vs. just flagging)
- **RequireClientData:** Require canvas/WebGL data (blocks headless browsers like Puppeteer)

### Tuning for Your Use Case

**Public Website (High Traffic):**
```go
MaxIPsPerFingerprint: 10  // More lenient
SuspiciousThreshold:  5
BlockOnExceed:        false  // Just monitor
```

**Login/Sensitive Areas (High Security):**
```go
MaxIPsPerFingerprint: 3  // Strict
SuspiciousThreshold:  2
BlockOnExceed:        true  // Active blocking
```

**Corporate/Internal (Shared IPs):**
```go
MaxIPsPerFingerprint: 50  // Very lenient (NAT/proxies)
SuspiciousThreshold:  20
BlockOnExceed:        false
```

### Monitoring

Check fingerprint statistics:

```bash
curl http://localhost:8080/fingerprint/stats
```

**Example Output:**
```json
{
  "total_fingerprints": 1247,
  "total_ips": 1523,
  "suspicious_fingerprints": 12,
  "blocked_ips": 34,
  "avg_ips_per_fingerprint": 1.2
}
```

---

## IP Rules & Geolocation

### Per-IP Controls (60+ Fields)

Each IP rule supports extensive configuration:

**Time-Based:**
```json
{
  "ip": "198.51.100.100",
  "allowed_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
  "allowed_days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
  "timezone": "America/New_York"
}
```

**Path & Method:**
```json
{
  "ip": "198.51.100.100",
  "allowed_paths": ["/api/*", "/public/*"],
  "blocked_paths": ["/admin/*"],
  "allowed_methods": ["GET", "POST"],
  "blocked_methods": ["DELETE", "PUT"]
}
```

**Size Limits:**
```json
{
  "ip": "198.51.100.100",
  "max_upload_size": 10485760,     // 10MB
  "max_url_length": 2048,           // 2KB
  "max_header_size": 8192           // 8KB
}
```

**Rate Limiting:**
```json
{
  "ip": "198.51.100.100",
  "min_request_interval": 1  // Min seconds between requests
}
```

**User-Agent Filtering:**
```json
{
  "ip": "198.51.100.100",
  "blocked_user_agents": ["*bot*", "*crawler*", "*scrapy*"],
  "block_headless": true,
  "block_bots": true
}
```

**Pattern Matching:**
- Use `*` for wildcards
- `*admin*` matches any path containing "admin"
- `/api/*` matches paths starting with "/api/"

### Geolocation Rules

**Block by Country:**
```json
{
  "geo_rules": [
    {
      "country_code": "KP",
      "action": "block",
      "reason": "Sanctioned country"
    }
  ]
}
```

**Challenge by Country:**
```json
{
  "geo_rules": [
    {
      "country_code": "CN",
      "action": "challenge",
      "throttle_percent": 40,
      "reason": "High-risk region"
    }
  ]
}
```

**Actions:**
- `allow` - No restrictions
- `challenge` - Require challenge completion
- `block` - Immediate 403 rejection

---

## Rate Limiting

### Global Limits

Edit `waf/adaptive.go`:

```go
rateLimiter := ddos.NewRateLimiter(
    100,              // Max requests per IP per minute
    time.Minute,      // Time window
    10,               // Max concurrent connections per IP
)
```

### Per-IP Limits

In `config/ip_rules.json`:

```json
{
  "global_rules": {
    "max_requests_per_ip": 100,
    "max_connections_per_ip": 10
  }
}
```

### Recommended Settings

**API Endpoints:**
- 50-200 requests/minute
- 5-10 concurrent connections

**Web Applications:**
- 100-500 requests/minute
- 10-20 concurrent connections

**Static Assets:**
- 500-1000 requests/minute
- 20-50 concurrent connections

---

## Production Checklist

### Pre-Deployment

- [ ] **Review configuration** - Check all settings in main.go
- [ ] **Test builds** - Verify `go build` succeeds
- [ ] **Configure CAPTCHA** - Set API keys if using hCaptcha/Turnstile
- [ ] **Set geo rules** - Configure country blocking/challenging
- [ ] **Test challenges** - Verify challenge pages work in browser
- [ ] **Test fingerprinting** - Check fingerprint collection works
- [ ] **Review logs** - Ensure log directory `./logs/` is writable
- [ ] **Load test** - Verify rate limits under expected traffic
- [ ] **Document changes** - Update internal docs with custom settings

### Deployment

- [ ] **Build binary** - `go build -o rhinowaf ./cmd/rhinowaf`
- [ ] **Set environment variables** - CAPTCHA keys if needed
- [ ] **Start WAF** - `./rhinowaf` or use systemd/docker
- [ ] **Verify startup** - Check logs for expected features enabled
- [ ] **Test endpoints** - Ensure backend proxy works
- [ ] **Monitor logs** - Watch `./logs/ddos.log` for attacks

### Post-Deployment

- [ ] **Monitor metrics** - Check fingerprint stats regularly
- [ ] **Review attack logs** - Analyze blocked IPs/patterns
- [ ] **Tune thresholds** - Adjust based on legitimate traffic patterns
- [ ] **Update IP rules** - Ban persistent attackers
- [ ] **Scale if needed** - Add more WAF instances for high traffic
- [ ] **Backup config** - Save `config/ip_rules.json` regularly
- [ ] **Plan updates** - Review release notes for new features

### Security Best Practices

- [ ] **Use HTTPS** - Put WAF behind nginx/caddy with TLS
- [ ] **Rotate secrets** - Change CAPTCHA keys periodically
- [ ] **Log retention** - Implement log rotation for `./logs/`
- [ ] **Access control** - Restrict who can modify configs
- [ ] **Monitoring** - Set up alerts for high attack rates
- [ ] **Backup** - Regular backups of configs and logs
- [ ] **Updates** - Keep RhinoWAF updated for security patches

---

## Troubleshooting

### Issue: Legitimate users being blocked

**Solution:** Reduce strictness

```go
// Loosen fingerprinting
MaxIPsPerFingerprint: 10  // Increase from 5
BlockOnExceed:        false  // Just monitor

// Loosen rate limits
max_requests_per_ip: 200  // Increase from 100
```

### Issue: Bots still getting through

**Solution:** Increase strictness

```go
// Stricter fingerprinting
MaxIPsPerFingerprint: 3  // Decrease from 5
RequireClientData:    true  // Require canvas/WebGL

// Add CAPTCHA
DefaultType: challenge.TypeHCaptcha  // Upgrade from JavaScript
```

### Issue: High CPU usage

**Solution:** Optimize challenge difficulty

```go
// Reduce proof-of-work difficulty
Difficulty: 3  // Down from 5-6

// Or switch to lighter challenge
DefaultType: challenge.TypeJavaScript
```

### Issue: CAPTCHA not working

**Solution:** Verify API keys

```bash
# Check environment variables are set
echo $HCAPTCHA_SITE_KEY
echo $HCAPTCHA_SECRET

# Verify keys are correct from provider dashboard
# Restart WAF after setting keys
```

---

## Support

- **Documentation:** See `docs/` directory for detailed guides
- **Examples:** Check `docs/*_EXAMPLES.md` for configuration samples
- **Issues:** GitHub issue tracker
- **Security:** See SECURITY.md for vulnerability reporting

---

**Version:** 2.0  
**Status:** Production Ready  
**License:** AGPL-3.0
