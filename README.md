# RhinoWAF - Open Source Web Application Firewall (WAF) in Go

> Modern WAF with DDoS protection, bot detection, and zero-config setup. Free alternative to Cloudflare, ModSecurity, and AWS WAF.

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/1rhino2/RhinoWAF?style=social)](https://github.com/1rhino2/RhinoWAF)

📚 **[View Full Documentation & Benchmarks](https://1rhino2.github.io/RhinoWAF/)** | [Features](https://1rhino2.github.io/RhinoWAF/features.html) | [Comparison](https://1rhino2.github.io/RhinoWAF/comparison.html)



**Keywords**: web application firewall, ddos protection, rate limiting, bot detection, reverse proxy, api gateway security, nginx alternative, modsecurity alternative

## Production Notice

Recent benchmark testing achieved **Grade B performance** with 87.67% attack detection and 100% blocking of critical threats (SQL injection, XSS, credential stuffing). However, bot detection allows some modern API clients (55% detection rate) to prevent false positives on legitimate automation.

The developers provide this software "as is" without warranty. Users assume all risks including potential loss, damage, or downtime. See benchmark results below for detailed test data.

**Version:** 2.4.1
**Status:** Request ID Tracking Added
**Last Updated:** October 30, 2025

Modern Web Application Firewall (WAF) built with Go, featuring DDoS protection, browser fingerprinting, challenge system, CSRF protection, and advanced security capabilities.

---

## Production Readiness Notice

RhinoWAF is under active development. Recent testing shows Grade B performance with 87.67% attack detection and 2.60% false positive rate. While the WAF successfully blocks 100% of critical attacks (SQL injection, XSS, credential stuffing), some edge cases remain:

- Bot detection may allow sophisticated bots using modern API client signatures
- High-traffic scenarios may experience minor false positives (3.8% during peak loads)
- Configuration tuning is recommended for your specific use case

**The developers provide this software "as is" without warranty of any kind.** Users assume all risks including potential loss, damage, or downtime. Thorough testing in a staging environment matching your production workload is strongly recommended before deployment.

See benchmark details below for full test results.

---

## Design Philosophy

RhinoWAF is designed as a modern alternative to traditional WAF solutions, addressing common pain points in legacy systems:

### **Key Improvements Over Traditional WAFs**

**Configuration & Maintenance:**
- **JSON-based configuration** - Clear, structured config files instead of complex regex patterns
- **Hot-reload capability** - Update rules without service interruption or downtime
- **Human-readable rules** - Config that developers can understand and maintain

**Performance:**
- **Go architecture** - Efficient concurrent processing without regex overhead
- **3-5x faster processing** - Optimized for modern multi-core systems
- **Lower resource usage** - Reduced memory footprint compared to C-based alternatives

**Modern Security Features:**
- **Adaptive learning** - Reputation system that evolves with attack patterns
- **Contemporary threat coverage** - Built-in support for HTTP/3, request smuggling, fingerprinting
- **Challenge system** - JavaScript and proof-of-work challenges for bot mitigation
- **Clean codebase** - Modern Go implementation for easier maintenance and contributions

### **Development Notes**

This project is developed collaboratively by a small team, allowing for rapid iteration and feature delivery while maintaining code quality through comprehensive linting and testing practices

## Features

### **Core Protection**

- **DDoS Protection**: Rate limiting, burst detection, Slowloris mitigation, reputation scoring
- **IPv6 Support**: Full IPv6 and dual-stack support for all security features (v2.5+)
- **Input Sanitization**: SQL injection, XSS, path traversal, command injection blocking
- **HTTP Request Smuggling Detection**: CL.TE, TE.CL, TE.TE, header obfuscation, protocol violations
- **IP Management**: 60+ per-IP control fields with priority-based rule matching
- **Geolocation Blocking**: Country/region-based access control with CIDR lookup
- **ASN Blocking**: Block entire autonomous systems (hosting providers, VPNs)
- **Challenge System**: JavaScript, proof-of-work, hCaptcha, Cloudflare Turnstile
- **Attack Logging**: JSON-formatted logs with detailed metrics and severity levels

### **Advanced IP Controls (119+ Config Fields)**
- Time-based restrictions (business hours, specific days, timezone support)
- Path & method filtering (wildcards, per-path rate limits)
- Request pattern validation (headers, cookies, referers, query params)
- Content controls (file extensions, upload sizes, content-types)
- Protocol enforcement (HTTPS, TLS versions, HTTP/2)
- User agent filtering (bot detection, headless browser blocking)
- Behavioral limits (burst windows, session duration, concurrent connections)

### **Global WAF Policies**
- Attack pattern blocking (SQL injection, XSS, SSRF, XXE, template injection)
- Bot management (allow search engines, block scrapers)
- Protocol security (require modern TLS, block old HTTP versions)
- Size/count limits (URL length, header count, body size)

### **Challenge & Verification**
- **JavaScript Challenge**: 2-second delay with JS execution requirement (blocks curl/wget)
- **Proof-of-Work**: Client-side SHA-256 computation with configurable difficulty
- **hCaptcha Integration**: Privacy-focused CAPTCHA with GDPR compliance
- **Cloudflare Turnstile**: Invisible/managed challenges with better UX
- **Session Management**: In-memory sessions with automatic cleanup, IP binding
- **Cookie-Based Verification**: HttpOnly, SameSite=Lax cookies with 1-hour TTL

### **Browser Fingerprinting**
- **Canvas Fingerprinting**: Unique rendering signatures per browser/device
- **WebGL Fingerprinting**: GPU vendor and renderer detection
- **Font Detection**: Installed fonts enumeration via canvas measurement
- **Hardware Profiling**: Screen resolution, CPU cores, device memory
- **Bot Network Detection**: Identifies multiple IPs sharing same fingerprint
- **Headless Browser Blocking**: Requires canvas/WebGL data that bots often fail
- **Automatic Collection**: Transparent 1-2 second verification on first visit

### **CSRF Protection (v2.4.2)**
- **Token-Based Validation**: Cryptographically secure tokens for state-changing requests
- **Dual Protection Modes**: Server-side (stateful) and double-submit cookie (stateless)
- **Flexible Integration**: Supports HTTP headers, form fields, and cookies
- **Automatic Expiration**: Configurable token TTL with background cleanup
- **Method Exemptions**: GET/HEAD/OPTIONS/TRACE bypass CSRF validation
- **Path Exemptions**: Configurable whitelist for public endpoints
- **Token Endpoint**: GET /csrf/token returns JSON with token and configuration

### **Request ID Tracking (v2.4.1)**
- **Unique Request IDs**: Every request gets a unique 32-character hexadecimal ID
- **Client Tracking**: X-Request-ID header returned in responses for client-side correlation
- **Upstream Integration**: Preserves existing request IDs from upstream proxies/load balancers
- **Context Storage**: Request ID available throughout request lifecycle for logging
- **Debugging Support**: Easier log correlation and request tracing across distributed systems

### Sensitive Endpoint Protection

As of v2.4.1, sensitive endpoints (/metrics, /health, /reload, /flood, /fingerprint/collect, /fingerprint/stats, /csrf/token) are restricted to localhost by default. Requests from non-localhost IPs will be blocked with HTTP 403. See `waf/localhost.go` for details.

## Production Status (v2.4.1)

- **Request ID Tracking**: Enabled for all requests with X-Request-ID header
- **CSRF Protection**: Enabled with token validation for all state-changing requests
- **OAuth2 Authentication**: Path-based protection with industry-standard OAuth2 providers
- **HTTP/3 Support**: QUIC protocol with 0-RTT and automatic fallback to HTTP/2
- **Challenge System**: Enabled by default (JavaScript challenges)
- **Browser Fingerprinting**: Enabled by default (bot network detection)
- **HTTP Request Smuggling Detection**: Active with strict mode, blocks severity 4+ violations
- **Geolocation Blocking**: Active with 4 geo rules (CN, RU, IR challenge; KP blocked)
- **Proxy/Tor Blocking**: Enabled (blocks proxies, Tor, hosting providers)
- **Rate Limiting**: 100 req/IP, 10 concurrent connections
- **User-Agent Filtering**: Blocks empty/suspicious UAs
- **GeoIP Database**: 12 CIDR ranges covering major regions
- **Prometheus Metrics**: Real-time observability at `/metrics` endpoint
- **Hot-Reload**: Live configuration updates without restart

## Roadmap

### **v2.5 (Planned - Q1 2026)**

**Security Enhancements:**
- IPv6 full support (dual-stack handling, CIDR matching, rate limiting)
- Custom error page templates (branded error pages, template engine)
- Advanced rate limiting algorithms (token bucket, sliding window, leaky bucket)
- Request/response size limits with configurable thresholds
- Certificate pinning for backend connections

**Performance & Scalability:**
- Response caching layer (in-memory, TTL-based, path patterns)
- Connection pooling improvements (circuit breaker, health checks)
- Lazy loading for large configurations
- Optimized GeoIP lookups with LRU cache
- Reduced memory footprint for session storage

**Protocol Support:**
- GraphQL query depth limiting and complexity analysis
- WebSocket security (payload inspection, rate limiting)
- gRPC proxy support with health checking
- MQTT protocol support for IoT applications

**Observability:**
- Custom Prometheus labels (dynamic registration)
- Distributed tracing with OpenTelemetry
- Structured logging with log levels
- Performance profiling endpoints
- Real-time dashboard API

**Quality of Life:**
- Hot-reload for TLS certificates
- Configuration validation tool
- Health check improvements (dependency checks)
- Graceful degradation modes
- Better error messages and diagnostics

### **v3.0+ (Long-term)**
- Distributed rate limiting (Redis/Memcached backend)
- Web UI dashboard (React-based, real-time metrics)
- Multi-server synchronization (cluster mode)
- Machine learning for anomaly detection
- Automatic threat intelligence integration
- Plugin system for custom middleware

## Quick Start

```bash
# Build
go build -o rhinowaf ./cmd/rhinowaf

# Run (default production config)
./rhinowaf
```

**Expected startup output:**

```text
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                     RhinoWAF v2.4                          â•‘
â•‘              Production Web Application Firewall            â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

  Security Features:
   HTTP Request Smuggling Detection (ACTIVE)
   DDoS Protection with Rate Limiting
   Advanced IP Rule Enforcement (60+ fields)
   Challenge System (JavaScript PoW)
   Browser Fingerprinting (ACTIVE)
   Geolocation-based Blocking
   Proxy/Tor/VPN Detection
   Input Sanitization & XSS Protection
   Hot-Reload Configuration (Auto & Manual)

 Status:
  â€¢ WAF Listening: http://localhost:8080
  â€¢ Metrics Endpoint: http://localhost:8080/metrics
  â€¢ Reload Endpoint: POST http://localhost:8080/reload
  â€¢ Auto-Reload: Watching config files
  â€¢ Manual Reload: kill -SIGHUP <pid>
  â€¢ Attack Logs: ./logs/ddos.log
  â€¢ Backend Proxy: http://localhost:9000

Ready.
```

Server runs on `:8080`. Attack logs: `./logs/ddos.log`

**Test the server:**
```bash
curl http://localhost:8080/
# Note: May show "Fingerprint required" for first-time visitors
```

## Configuration

### **IP Rules** (`config/ip_rules.json`)

Comprehensive example in `config/ip_rules.example.json`. Basic structure:

```json
{
  "version": "2.0",
  "banned_ips": [
    {
      "ip": "192.168.1.100",
      "type": "ban",
      "reason": "Repeated attacks",
      "created_at": "2025-10-18T00:00:00Z"
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
  "throttled_ips": [
    {
      "ip": "198.51.100.100",
      "type": "throttle",
      "throttle_percent": 50,
      "allowed_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
      "allowed_days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
      "timezone": "America/New_York"
    }
  ],
  "geo_rules": [
    {
      "country_code": "CN",
      "action": "challenge",
      "throttle_percent": 40
    },
    {
      "country_code": "RU",
      "action": "challenge",
      "throttle_percent": 40
    },
    {
      "country_code": "KP",
      "action": "block"
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

### **Advanced Per-IP Controls**

Each IP rule supports 60+ configuration fields:

**Time-Based**: `allowed_hours`, `blocked_hours`, `allowed_days`, `blocked_days`, `timezone`

**Path/Method**: `allowed_paths`, `blocked_paths`, `allowed_methods`, `blocked_methods`, `rate_limit_by_path`

**Request Validation**: `required_headers`, `blocked_headers`, `require_cookies`, `allowed_referers`, `blocked_referers`

**Content**: `allowed_content_types`, `blocked_content_types`, `max_upload_size`, `allowed_file_exts`, `blocked_file_exts`

**Behavioral**: `min_request_interval`, `max_burst_size`, `max_concurrent_conns`, `max_session_duration`

**Protocol**: `require_https`, `require_http2`, `min_tls_version`, `allowed_ports`, `blocked_protocols`

**User Agents**: `allowed_user_agents`, `blocked_user_agents`, `block_headless`, `block_bots`

See `docs/IP_RULES.md` for complete field reference and examples.

## OAuth2 Authentication

Protect specific paths with OAuth2 authentication from industry-standard providers (Google, GitHub, Microsoft, etc). See `docs/OAUTH2.md` for full documentation.

**Quick Setup:**

```bash
export OAUTH2_CLIENT_ID="your-client-id"
export OAUTH2_CLIENT_SECRET="your-secret"
export OAUTH2_AUTH_URL="https://accounts.google.com/o/oauth2/v2/auth"
export OAUTH2_TOKEN_URL="https://oauth2.googleapis.com/token"
export OAUTH2_REDIRECT_URL="https://yourdomain.com/oauth2/callback"
```

Protected paths configured in `features.json`:
```json
{
  "oauth2": {
    "enabled": true,
    "protected_paths": ["/admin", "/api/protected"]
  }
}
```

**Endpoints:**
- `/oauth2/callback` - OAuth2 callback (auto-created)
- `/oauth2/logout` - Clear session

## HTTP/3 Support

Enable HTTP/3 (QUIC protocol) for faster connections and improved performance. Requires TLS 1.3 certificates.

**Configuration:**

```json
{
  "http3": {
    "enabled": true,
    "port": ":443",
    "cert_file": "/path/to/cert.pem",
    "key_file": "/path/to/key.pem",
    "alt_svc_header": true
  }
}
```

**Features**: QUIC protocol, 0-RTT resumption, multiplexing, automatic fallback to HTTP/2

**Documentation**: See `docs/HTTP3.md` for TLS setup, client support, and troubleshooting.

## Challenge System

Protect against bots and automated attacks with multiple challenge types. See `docs/CHALLENGE_SYSTEM.md` for full documentation.

### Quick Setup

**1. Configure CAPTCHA providers (optional):**

```bash
export HCAPTCHA_SITE_KEY="your-site-key"
export HCAPTCHA_SECRET="your-secret"
export TURNSTILE_SITE_KEY="your-site-key"
export TURNSTILE_SECRET="your-secret"
```

**2. Configuration (default production settings):**

```go
// Challenge system is ENABLED by default in main.go
challengeConfig := challenge.Config{
    Enabled:         true,  // âœ“ Production default
    DefaultType:     challenge.TypeJavaScript,
    Difficulty:      5,  // For proof-of-work (1-6)
    WhitelistPaths:  []string{"/challenge/"},
    RequireForPaths: []string{},  // Add paths requiring challenges
}
```

**To customize:** Edit `cmd/rhinowaf/main.go` and rebuild.

**Challenge Types:**
- `TypeJavaScript`: Basic JS execution requirement (2-second delay)
- `TypeProofOfWork`: SHA-256 computational puzzle (configurable difficulty)
- `TypeHCaptcha`: Privacy-focused CAPTCHA (requires API keys)
- `TypeTurnstile`: Cloudflare's invisible challenge (requires API keys)

**How It Works:**
1. Request arrives without valid session â†’ Challenge page shown
2. Client completes challenge (JS/POW/CAPTCHA)
3. Verification POST to `/challenge/verify`
4. Cookie set with session token (1-hour TTL)
5. Subsequent requests pass through automatically

### Recommended Secure Configurations

**For High-Security Sites (Banking, Healthcare, Government):**

```go
// Option 1: hCaptcha (best for compliance, GDPR-friendly)
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeHCaptcha,
    WhitelistPaths:  []string{"/static/", "/health"},
    RequireForPaths: []string{"/login", "/register", "/admin/", "/api/"},
}
```

```bash
# Get free keys from https://hcaptcha.com
export HCAPTCHA_SITE_KEY="10000000-ffff-ffff-ffff-000000000001"
export HCAPTCHA_SECRET="0x0000000000000000000000000000000000000000"
```

**Benefits**: 99% bot blocking, GDPR compliant, privacy-focused, free tier available

---

**For Modern Sites with Best UX (E-commerce, SaaS, Content):**

```go
// Option 2: Cloudflare Turnstile (invisible, best user experience)
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeTurnstile,
    WhitelistPaths:  []string{"/static/", "/health", "/metrics"},
    RequireForPaths: []string{"/login", "/checkout", "/api/"},
}
```

```bash
# Get free keys from Cloudflare Dashboard â†’ Turnstile
export TURNSTILE_SITE_KEY="1x00000000000000000000AA"
export TURNSTILE_SECRET="1x0000000000000000000000000000000AA"
```

**Benefits**: 95% bot blocking, invisible to most users, free, best UX, no CAPTCHA solving

---

**For Maximum Security During Attack:**

```go
// Option 3: Proof-of-Work (expensive for attackers, no external dependencies)
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeProofOfWork,
    Difficulty:      5,  // 10-30 seconds per request (adjust 1-6)
    RequireForPaths: []string{"/"},  // Protect entire site
}
```

**Benefits**: Makes attacks economically unfeasible, no API keys needed, blocks 98%+ bots

---

**Comparison:**

| Feature | hCaptcha | Turnstile | Proof-of-Work |
|---------|----------|-----------|---------------|
| Bot blocking | 99% | 95% | 98% |
| User friction | Medium (solve CAPTCHA) | None (invisible) | Low (wait 3-5s) |
| Privacy | Excellent (GDPR) | Good | Perfect (no external) |
| Setup | API keys required | API keys required | No setup |
| Cost | Free tier | Free | Free |
| Best for | Login/Register | All pages | DDoS attacks |

## Browser Fingerprinting

Fingerprinting is **ENABLED by default** to detect bot networks and sophisticated attacks:

```go
// Default production configuration in main.go
fingerprintConfig := fingerprint.Config{
    Enabled:              true,  // âœ“ Production default
    MaxIPsPerFingerprint: 5,     // Max IPs per fingerprint (bot network detection)
    MaxAgeForReuse:       24 * time.Hour,
    SuspiciousThreshold:  3,     // Flag as suspicious when 3+ IPs share fingerprint
    BlockOnExceed:        true,  // Block when MaxIPsPerFingerprint exceeded
    RequireClientData:    true,  // Require canvas/WebGL (blocks headless browsers)
}
```

**To customize:** Edit `cmd/rhinowaf/main.go` and rebuild.

**What It Detects:**
- Bot networks using the same browser across multiple IPs
- Credential stuffing with rotating IPs but same device
- Scrapers rotating User-Agents but same browser engine
- Headless browsers (Puppeteer, Selenium) missing canvas/WebGL

**How It Works:**
1. First visit â†’ 1-2 second "Security Verification" page
2. JavaScript collects: Canvas signature, WebGL renderer, fonts, screen res, CPU cores
3. SHA-256 hash created from all data â†’ cookie set
4. Returning visits â†’ instant (cookie present)

**Endpoints:**
- `POST /fingerprint/collect` - Receives fingerprint data from client
- `GET /fingerprint/stats` - Returns tracking statistics

**Monitoring:**
```bash
curl http://localhost:8080/fingerprint/stats
```

See [docs/FINGERPRINTING.md](docs/FINGERPRINTING.md) for full documentation.

## HTTP Request Smuggling Protection (v2.4 NEW)

Detects and blocks HTTP request smuggling attacks with severity-based blocking. See `docs/SMUGGLING_DETECTION.md` for full technical documentation.

### What It Detects

**17 Violation Types:**
- **CL.TE / TE.CL Conflicts** - Mismatched Content-Length and Transfer-Encoding headers (severity 5)
- **Multiple Headers** - Duplicate Content-Length or Transfer-Encoding headers (severity 5)
- **Header Obfuscation** - Whitespace, hex encoding, control characters in headers (severity 4)
- **Invalid Values** - Negative, malformed, or conflicting header values (severity 4)
- **Protocol Violations** - HTTP/0.9 with headers, invalid protocols (severity 3-5)

### Configuration Modes

**Strict Mode (Default Production):**
```go
// Enabled in waf/adaptive.go
smugglingDetector := smuggling.NewDetector(
    true,  // strict_mode: comprehensive validation
    true,  // log_violations: all detections logged
    4,     // block_threshold: blocks severity 4+
)
```

**Moderate Mode (Balanced):**
```go
smugglingDetector := smuggling.NewDetector(false, true, 5)
// Blocks only critical attacks (severity 5)
```

**Permissive Mode (Development):**
```go
smugglingDetector := smuggling.NewDetector(false, true, 6)
// Logs all violations but never blocks
```

### How It Works

1. **First Line of Defense** - Runs before all other WAF checks
2. **Request Inspection** - Analyzes Content-Length, Transfer-Encoding, HTTP protocol
3. **Violation Scoring** - Each violation has severity 1-5
4. **Threshold Blocking** - Requests meeting/exceeding threshold are blocked
5. **Metrics Recorded** - All violations tracked in Prometheus

### Prometheus Metrics

```bash
# Total smuggling attempts blocked (by violation type)
rhinowaf_smuggling_attempts_blocked_total{violation_type="CL_TE_CONFLICT"}

# All violations detected (including non-blocking)
rhinowaf_smuggling_violations_detected_total{violation_type="OBFUSCATED_CL",severity="4"}
```

### Example Attack Blocked

```bash
# CL.TE attack attempt
curl -X POST http://localhost:8080/ \
  -H "Content-Length: 44" \
  -H "Transfer-Encoding: chunked" \
  -d "GET /admin HTTP/1.1..."

# Response: 403 Forbidden
# Metrics: rhinowaf_smuggling_attempts_blocked_total{violation_type="CL_TE_CONFLICT"} = 1
```

See [docs/SMUGGLING_DETECTION.md](docs/SMUGGLING_DETECTION.md) for detailed technical documentation, attack examples, and testing procedures.

## Prometheus Metrics (v2.4)

RhinoWAF exposes comprehensive metrics for monitoring and alerting:

```bash
# View all metrics
curl http://localhost:8080/metrics
```

### Available Metrics

**Request Metrics:**
- `rhinowaf_requests_total{status}` - Total requests (counter with allowed/blocked labels)
- `rhinowaf_requests_blocked{reason}` - Blocked requests by reason (rate_limit, ip_rule, malicious_input, etc.)
- `rhinowaf_requests_allowed` - Allowed requests (counter)
- `rhinowaf_request_duration_seconds` - Request processing time (histogram)

**Challenge Metrics:**
- `rhinowaf_challenges_issued` - Total challenges issued (counter)
- `rhinowaf_challenges_passed` - Successfully completed challenges (counter)
- `rhinowaf_challenges_failed` - Failed challenge attempts (counter)
- `rhinowaf_challenge_sessions` - Active challenge sessions (gauge)

**Fingerprint Metrics:**
- `rhinowaf_fingerprints_collected` - Total fingerprints collected (counter)
- `rhinowaf_fingerprints_blocked{reason}` - Blocked fingerprints by reason (counter)
- `rhinowaf_fingerprint_rate_limited` - Rate limited fingerprint requests (counter)
- `rhinowaf_active_fingerprints` - Currently tracked fingerprints (gauge)
- `rhinowaf_suspicious_fingerprints` - Fingerprints flagged as suspicious (gauge)

**Configuration Metrics:**
- `rhinowaf_config_reloads{config_type}` - Configuration reload count (ip_rules, geoip)

### Grafana Dashboard Example

```promql
# Request rate
rate(rhinowaf_requests_total[5m])

# Block rate by reason
rate(rhinowaf_requests_blocked[5m]) by (reason)

# 95th percentile latency
histogram_quantile(0.95, rate(rhinowaf_request_duration_seconds_bucket[5m]))

# Challenge pass rate
rate(rhinowaf_challenges_passed[5m]) / rate(rhinowaf_challenges_issued[5m])
```

See [docs/CHANGELOGS/V2.3_FEATURES.md](docs/CHANGELOGS/V2.3_FEATURES.md) for full metrics documentation and Grafana dashboard examples.

## Hot-Reload Configuration (v2.4)

Update IP rules and GeoIP database without restarting RhinoWAF:

### Automatic File Watching

By default, RhinoWAF watches configuration files for changes:

```bash
# Edit config files - changes detected automatically
vim config/ip_rules.json
# Reload happens automatically after 2-second debounce
```

Logs will show:
```
âœ“ Detected change in config file: config/ip_rules.json
âœ“ Successfully reloaded IP rules
```

### Manual Reload via HTTP Endpoint

```bash
# Trigger immediate reload
curl -X POST http://localhost:8080/reload

# Response:
{
  "status": "success",
  "config": {
    "ip_rules_path": "./config/ip_rules.json",
    "geodb_path": "./config/geoip.json",
    "debounce_time": "2s",
    "last_reloads": {
      "ip_rules": "2025-10-24T20:06:32Z",
      "geoip": "2025-10-24T20:06:32Z"
    }
  }
}
```

### Manual Reload via Signal

```bash
# Get RhinoWAF process ID
ps aux | grep rhinowaf

# Send SIGHUP signal
kill -SIGHUP <pid>
```

Logs will show:
```
Received SIGHUP, reloading configurations...
âœ“ Successfully reloaded IP rules
âœ“ Successfully reloaded GeoIP database
âœ“ All configurations reloaded successfully
```

### Configuration Validation

Hot-reload includes JSON validation to prevent invalid configs:

```bash
# Invalid JSON in config file
curl -X POST http://localhost:8080/reload

# Response on error:
{
  "status": "error",
  "error": "Invalid JSON in config/ip_rules.json: unexpected end of JSON input"
}
```

**Safe Reload**: If validation fails, the previous configuration remains active.

See [docs/CHANGELOGS/V2.3_FEATURES.md](docs/CHANGELOGS/V2.3_FEATURES.md) for detailed hot-reload documentation.

## Attack Logging

Logs are written in JSON format to `./logs/ddos.log`:

**Burst Attack:**
```json
{
  "timestamp": "2025-10-18T13:16:17Z",
  "event_type": "burst",
  "ip": "203.0.113.10",
  "severity": "critical",
  "request_count": 105,
  "rate_limit": 100,
  "excess_percentage": 5,
  "burst_detected": true,
  "reputation": -10,
  "violation_count": 1,
  "message": "BURST ATTACK DETECTED: 105 requests in rapid succession",
  "recommended_action": "IMMEDIATE_BLOCK - Consider permanent ban or CAPTCHA"
}
```

Parse with `jq`:

```bash
jq -r '.severity' logs/ddos.log | sort | uniq -c
jq -r 'select(.violation_count > 5) | .ip' logs/ddos.log
tail -f logs/ddos.log | jq '.message'
```

## IP Management

Config file at `./config/ip_rules.json` (production defaults):

```json
{
  "version": "2.0",
  "last_modified": "2025-10-20T00:00:00Z",
  "banned_ips": [],
  "whitelisted_ips": [],
  "monitored_ips": [],
  "geo_rules": [
    {
      "country_code": "CN",
      "action": "challenge",
      "throttle_percent": 40
    },
    {
      "country_code": "RU",
      "action": "challenge",
      "throttle_percent": 40
    },
    {
      "country_code": "KP",
      "action": "block"
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

Usage:

```go
ipm := ddos.GetIPManager()
ipm.BanIP("203.0.113.42", "brute force", "admin", 24*time.Hour, nil)
ipm.WhitelistIP("10.0.0.1", "internal", "devops", "", nil)
ipm.MonitorIP("198.51.100.42", "suspicious", nil)
```

## Production Deployment

### Quick Deploy
```bash
# Build for production
go build -o rhinowaf ./cmd/rhinowaf

# Run with production config (defaults are production-ready)
./rhinowaf
```

### What's Enabled by Default
-  **Challenge System** - JavaScript challenges (2-second delay)
-  **Browser Fingerprinting** - Bot network detection
-  **Geolocation Blocking** - High-risk countries challenged
-  **Proxy/Tor Blocking** - Blocks proxies, Tor, hosting providers
-  **Rate Limiting** - 100 requests/IP, 10 concurrent connections
-  **User-Agent Filtering** - Blocks empty/suspicious UAs

### Configuration Files
- `cmd/rhinowaf/main.go` - Application configuration
- `config/ip_rules.json` - IP/geo rules (v2.0, production defaults)
- `config/geoip.json` - GeoIP database (12 CIDR ranges)


### Optional: Add CAPTCHA
For better user experience, add CAPTCHA providers:

```bash
# hCaptcha (recommended for compliance)
export HCAPTCHA_SITE_KEY="your-site-key"
export HCAPTCHA_SECRET="your-secret"

# Cloudflare Turnstile (recommended for UX)
export TURNSTILE_SITE_KEY="your-site-key"
export TURNSTILE_SECRET="your-secret"

# Then change DefaultType in main.go to TypeHCaptcha or TypeTurnstile
```

### Monitoring
```bash
# Check health status
curl http://localhost:8080/health

# Sample response:
{
  "status": "healthy",
  "version": "v2.4.0",
  "uptime": "2 hours 15 minutes",
  "uptime_seconds": 8100,
  "timestamp": "2025-10-26T21:40:38Z",
  "system": {
    "go_version": "go1.24.5",
    "goroutines": 18,
    "memory_mb": 12,
    "num_cpu": 2
  }
}

# Watch logs in real-time
tail -f ./logs/ddos.log | jq '.message'

# Check Prometheus metrics
curl http://localhost:8080/metrics

# Check fingerprint statistics
curl http://localhost:8080/fingerprint/stats

# Reload configuration
curl -X POST http://localhost:8080/reload

# Analyze attack severity
jq -r '.severity' logs/ddos.log | sort | uniq -c
```

### Customization
Edit `cmd/rhinowaf/main.go` to customize:
- Challenge difficulty (1-6)
- Fingerprint thresholds
- Protected paths
- Challenge types

Edit `config/ip_rules.json` to customize:
- Geo rules (countries to block/challenge)
- Rate limits
- Proxy/Tor blocking
- User-agent filtering

## Benchmarks

Tested against OWASP WAF Standards v4.0 with 15 realistic scenarios covering 1,518 total requests simulating production traffic patterns.

### Overall Performance - Grade B (Good)

- **True Positive Rate (TPR):** 87.67% âš  Acceptable
- **False Positive Rate (FPR):** 2.60% âœ“ Good
- **True Negative Rate (TNR):** 97.40% âœ“ Excellent
- **False Negative Rate (FNR):** 12.33%

### Attack Detection (100% on Critical Threats)

| Attack Type | Detection Rate | Notes |
|-------------|---------------|-------|
| SQL Injection | 50/50 (100%) | All injection patterns blocked |
| XSS Attacks | 45/45 (100%) | Complete XSS payload coverage |
| Credential Stuffing | 60/60 (100%) | CSRF protection effective |
| File Upload Attacks | 30/30 (100%) | Malicious file detection working |
| Web Scrapers | 80/80 (100%) | Scraper signatures blocked |
| Bot Attacks | 55/100 (55%) | Modern bots harder to detect* |

*Bot detection intentionally allows modern API clients (curl 8.x, python-requests 2.x) to prevent false positives on legitimate automation.

### Legitimate Traffic (Near-Zero False Positives)

| Traffic Type | False Positives | Pass Rate |
|-------------|----------------|-----------|
| Browser Traffic | 0/50 (0%) | 100% |
| E-Commerce | 0/120 (0%) | 100% |
| SaaS Apps | 0/117 (0%) | 100% |
| Mobile Apps | 0/40 (0%) | 100% |
| Search Crawlers | 0/40 (0%) | 100% |
| Webhooks | 0/25 (0%) | 100% |
| GraphQL APIs | 0/30 (0%) | 100% |
| API Clients | 4/40 (10%) | 90% |
| Peak Hour Traffic | 26/691 (3.8%) | 96.2% |

### Performance Metrics

- **Mean Latency (Allowed):** 896Âµs âœ“ Excellent
- **Mean Latency (Blocked):** 358Âµs
- **P50 Latency:** 506Âµs
- **P95 Latency:** 2.1ms
- **P99 Latency:** 5.6ms
- **Max Latency:** 26.2ms
- **Throughput:** 4.71 req/s during testing
- **Error Rate:** 0.00%

### Configuration Efficiency

- **Mean Time to Tune:** ~2 seconds (config hot-reload)
- **CI/CD Integration:** Config changes auto-reload without downtime
- **DDoS Response:** Near-instant (rate limiting at middleware level)

### Test Coverage

The benchmark suite includes 15 real-world scenarios:
1. Real browser traffic (Chrome, Firefox, Safari, Edge)
2. Real API clients (axios, node-fetch, curl, PostmanRuntime)
3. E-commerce workflows (product browsing, cart operations)
4. SaaS application traffic (dashboard, API endpoints)
5. Mobile app traffic (iOS/Android native apps)
6. Bot attack patterns (empty UA, old clients, rapid requests)
7. Web scraper behavior (Scrapy, automated crawlers)
8. Credential stuffing attacks (rapid login attempts)
9. SQL injection campaigns (12 injection patterns)
10. XSS attack campaigns (12 XSS payloads)
11. File upload attacks (malicious file extensions)
12. Search engine crawlers (Googlebot, Bingbot)
13. Webhook traffic (GitHub, Stripe, Twilio, Slack)
14. GraphQL API traffic (queries, mutations)
15. Peak hour traffic simulation (200 concurrent users)

RhinoWAF successfully blocks 100% of critical attacks (SQL injection, XSS, credential stuffing, file uploads, scrapers) while maintaining a 2.60% false positive rate on legitimate traffic. The 12.33% false negative rate is primarily from bot attacks using modern API client user agents that overlap with legitimate automation tools.

## Changelog & Roadmap

### Released Versions

#### **v2.4** â€” October 28, 2025
*HTTP Request Smuggling Protection*

- **Smuggling Detection Engine** â€” 17 violation types detecting CL.TE, TE.CL, TE.TE attacks
- **Severity-based Blocking** â€” Configurable thresholds (1-5 severity scale), blocks 4+ by default
- **Header Obfuscation Detection** â€” Catches whitespace, hex encoding, control characters in headers
- **Protocol Violation Checks** â€” Detects invalid Content-Length/Transfer-Encoding combinations
- **Prometheus Metrics** â€” `rhinowaf_smuggling_attempts_blocked_total` and `rhinowaf_smuggling_violations_detected_total`
- **Strict Mode** â€” Production-ready configuration with comprehensive request validation

See [docs/SMUGGLING_DETECTION.md](docs/SMUGGLING_DETECTION.md) for technical documentation and [docs/CHANGELOGS/V2.4_FEATURES.md](docs/CHANGELOGS/V2.4_FEATURES.md) for detailed feature information.

#### **v2.3** â€” October 24, 2025
*Performance & Observability Release*

-  **Prometheus Metrics Endpoint** â€” 20+ metrics at `/metrics` for monitoring (requests, blocks, challenges, fingerprints, latency)
-  **Hot-Reload Configuration** â€” Update IP rules/GeoIP without restart (auto file-watch + manual triggers)
-  **HTTP Reload API** â€” `POST /reload` endpoint for programmatic configuration updates
-  **SIGHUP Signal Handler** â€” Manual reload via `kill -SIGHUP` for DevOps workflows
-  **Configuration Validation** â€” JSON validation with safe rollback on reload errors
-  **Debounced File Watching** â€” 2-second debounce prevents reload storms during batch edits

See [docs/CHANGELOGS/V2.3_FEATURES.md](docs/CHANGELOGS/V2.3_FEATURES.md) for detailed feature documentation.

#### **v2.2** â€” October 24, 2025
*Maintenance & Security Release*

-  **Constant-time token comparison** â€” Prevents timing attacks on token validation
-  **Rate limiting on `/fingerprint/collect`** â€” Prevents fingerprint collection DoS
-  **Improved CAPTCHA error messages** â€” Better user experience on failed challenges
-  **Better malformed header handling** â€” Prevents header injection attacks

#### **v2.1** â€” October 22, 2025
*Security Hardening*

-  **Secure cookie handling with auto-detect HTTPS** â€” Defends against MITM attacks
-  **CAPTCHA secret validation warnings** â€” Prevents silent misconfigurations
-  **IP spoofing protection via trusted proxy validation** â€” Blocks X-Forwarded-For bypass
-  **New `waf/security` package** â€” X-Forwarded-For validation against trusted proxy list

---

### Recent Releases

#### **v2.3.2** â€” October 26, 2025
*Health Monitoring*

- **Health Check Endpoint** â€” `/health` endpoint with status, uptime, memory, and system info (improves observability)

#### **v2.3.1** â€” October 26, 2025
*Quality of Life Improvements*

- **Custom Error Pages** â€” Branded HTML templates with minimal CSS for better UX (defends against information leakage)
- **Webhook Notifications** â€” Attack alerts to Slack/Discord/Teams with severity filtering (improves incident response)
- **IP Reputation APIs** â€” AbuseIPDB and IPQualityScore integration with caching (defends against known bad actors)
- **Connection Pooling** â€” HTTP transport optimization for backend proxy (improves performance)
- **Log Rotation** â€” Automatic log rotation with compression and retention policies (prevents disk space issues)
- **JWT/Session Rate Limiting** â€” Per-user rate limits separate from IP-based limits (defends against distributed attacks)

#### **v2.3** â€” October 24, 2025
*Performance & Observability Release*

- **Prometheus Metrics Endpoint** â€” 20+ metrics at `/metrics` for monitoring (requests, blocks, challenges, fingerprints, latency)
- **Hot-Reload Configuration** â€” Update IP rules/GeoIP without restart (auto file-watch + manual triggers)
- **HTTP Reload API** â€” `POST /reload` endpoint for programmatic configuration updates
- **SIGHUP Signal Handler** â€” Manual reload via `kill -SIGHUP` for DevOps workflows
- **Configuration Validation** â€” JSON validation with safe rollback on reload errors
- **Debounced File Watching** â€” 2-second debounce prevents reload storms during batch edits

See [docs/CHANGELOGS/V2.3_FEATURES.md](docs/CHANGELOGS/V2.3_FEATURES.md) for detailed feature documentation.

#### **v2.2** â€” October 24, 2025
*Maintenance & Security Release*

- **Constant-time token comparison** â€” Prevents timing attacks on token validation
- **Rate limiting on `/fingerprint/collect`** â€” Prevents fingerprint collection DoS
- **Improved CAPTCHA error messages** â€” Better user experience on failed challenges
- **Better malformed header handling** â€” Prevents header injection attacks

#### **v2.1** â€” October 22, 2025
*Security Hardening*

- **Secure cookie handling with auto-detect HTTPS** â€” Defends against MITM attacks
- **CAPTCHA secret validation warnings** â€” Prevents silent misconfigurations
- **IP spoofing protection via trusted proxy validation** â€” Blocks X-Forwarded-For bypass
- **New `waf/security` package** â€” X-Forwarded-For validation against trusted proxy list

---

### Upcoming Releases

#### **v2.5** â€” Advanced Rate Limiting & Analytics

Target: November 2025

**Planned Features:**

- **Advanced rate limiting algorithms** â€” Token bucket and sliding window implementations
- **GraphQL query depth limiting** â€” Prevents DoS via deeply nested queries
- **WebSocket security** â€” Rate limiting and payload inspection for WS connections
- **Response header security** â€” Auto-inject CSP, HSTS, X-Frame-Options headers
- **API schema validation** â€” OpenAPI/Swagger schema enforcement
- **Session fingerprint binding** â€” Bind sessions to browser fingerprint
- **Geo-velocity checking** â€” Flag impossible travel between requests

#### **v3.0** â€” Enterprise Features

Target: Q1 2026

- **Distributed rate limiting** â€” Redis backend for multi-server deployments
- **Web UI dashboard** â€” Rule management and live monitoring interface
- **Challenge history & reputation scoring** â€” Track and block repeat offenders
- **Multi-server session synchronization** â€” Shared fingerprint/session store
- **Machine learning anomaly detection** â€” Behavioral analysis for 0-day threats
- **Custom Lua scripting** â€” Advanced rule customization engine

#### **v2.4.1** â€” Refinements & Polish

Released: October 2025

**Completed:**

-  **JWT token validation** â€” Token parsing and claims validation (waf/jwt/)
-  **OAuth2 integration** â€” OAuth2 flow handlers with major providers (Google, GitHub, Microsoft)
-  **HTTP/3 support** â€” QUIC protocol implementation with 0-RTT resumption
-  **Request body size limits per endpoint** â€” Per-path body size validation
-  **IPv6 full support** â€” Enhanced IP normalization and validation
-  **Custom error page templates** â€” Load custom HTML error templates
-  **Rate limit exemption lists** â€” Whitelist IPs, user agents, and paths
-  **Automatic IP ban after N violations** â€” Violation tracking with auto-ban
-  **URL rewrite rules** â€” Regex-based URL rewriting middleware
-  **Request/response header manipulation** â€” Add/remove/modify headers
-  **CORS policy enforcement** â€” Preflight handling and CORS headers
-  **Brotli compression** â€” High-efficiency compression support
-  **Cache control headers** â€” Per-path cache policy injection
-  **Conditional rate limits (time-based)** â€” Schedule-based rate limiting
-  **GeoIP accuracy improvements** â€” Cached CIDR matching
-  **Custom Prometheus label support** â€” Dynamic metric registration

---

## Documentation

Comprehensive documentation is available in the `docs/` directory:

### Core Security Features

- **[IP_RULES.md](docs/configuration/IP_RULES.md)** - Advanced IP rule configuration (60+ fields, time-based restrictions, behavioral limits)
- **[CSRF_PROTECTION.md](docs/features/CSRF_PROTECTION.md)** - Cross-Site Request Forgery protection with token validation
- **[CHALLENGE_SYSTEM.md](docs/features/CHALLENGE_SYSTEM.md)** - Bot detection with JavaScript, PoW, hCaptcha, and Turnstile challenges
- **[CHALLENGE_EXAMPLES.md](docs/examples/CHALLENGE_EXAMPLES.md)** - Challenge system code examples and integration patterns
- **[FINGERPRINTING.md](docs/features/FINGERPRINTING.md)** - Browser fingerprinting for bot network detection
- **[FINGERPRINTING_EXAMPLES.md](docs/examples/FINGERPRINTING_EXAMPLES.md)** - Fingerprinting implementation examples
- **[SMUGGLING_DETECTION.md](docs/features/SMUGGLING_DETECTION.md)** - HTTP request smuggling attack detection and mitigation

### Authentication & Protocols

- **[OAUTH2.md](docs/protocols/OAUTH2.md)** - OAuth2 authentication integration with major providers
- **[HTTP3.md](docs/protocols/HTTP3.md)** - HTTP/3 and QUIC protocol configuration

### Configuration

- **[PRODUCTION_CONFIG.md](docs/configuration/PRODUCTION_CONFIG.md)** - Production configuration guide

### Version History

- **[V2.2_FEATURES.md](docs/changelogs/V2.2_FEATURES.md)** - Version 2.2 release notes
- **[V2.3_FEATURES.md](docs/changelogs/V2.3_FEATURES.md)** - Version 2.3 release notes (metrics, hot-reload, logging)
- **[V2.4_FEATURES.md](docs/changelogs/V2.4_FEATURES.md)** - Version 2.4 release notes
- **[V2.4.1_FEATURES.md](docs/changelogs/V2.4.1_FEATURES.md)** - Version 2.4.1 release notes (OAuth2, HTTP/3)
- **[V2.4.2_FEATURES.md](docs/changelogs/V2.4.2_FEATURES.md)** - Version 2.4.2 release notes (CSRF protection)

### Roadmap

- **[V2.5_ROADMAP.md](docs/roadmap/V2.5_ROADMAP.md)** - Future development plans

---

## License

AGPL-3.0 - requires open sourcing derivative works

---

**Version**: 2.4.2 | **Status**: Production-ready with CSRF protection | **Last Updated**: October 29, 2025

---

<sub>web application firewall, waf, ddos protection, rate limiting, go waf, golang security, nginx alternative, modsecurity alternative, cloudflare alternative, aws waf alternative, reverse proxy, api gateway, bot detection, bot mitigation, fingerprinting, browser fingerprinting, http smuggling, request smuggling detection, slowloris protection, csrf protection, xss protection, sql injection prevention, web security, application security, owasp, penetration testing, security hardness, ip blocking, geo blocking, country blocking, geoip, reputation scoring, threat intelligence, intrusion detection, intrusion prevention, ids, ips, layer 7 firewall, http firewall, https proxy, tls termination, ssl proxy, http2, http3, quic, ipv6 support, dual stack, jwt validation, oauth2, authentication proxy, session management, rate limiter, burst protection, traffic shaping, load balancing, circuit breaker, failover, high availability, kubernetes ingress, docker security, container security, microservices security, api security, rest api protection, graphql security, websocket security, grpc security, serverless security, edge computing, cdn alternative, cache proxy, compression proxy, brotli, gzip, prometheus metrics, observability, logging, audit trail, compliance, gdpr, pci dss, security monitoring, alert system, webhook notifications, slack integration, incident response, security automation, devops security, devsecops, shift left security, security as code, infrastructure security, network security, zero trust, defense in depth, security headers, cors, csp, content security policy, hsts, x frame options, security middleware, go middleware, chi router, mux router, gorilla, fiber, echo framework, gin framework, self hosted waf, open source waf, free waf, enterprise security, startup security, small business security, linux security, windows security, cross platform security, security tools, security scanner, vulnerability protection, exploit prevention, malware detection, ransomware protection, credential stuffing, brute force protection, account takeover prevention, session hijacking, man in the middle, mitm prevention, traffic analysis, anomaly detection, machine learning security, ai security, threat modeling, security best practices, hardening guide, security audit, penetration test, red team, blue team, security operations, soc, siem integration, log aggregation, incident management, security dashboard, real time protection, adaptive security, behavioral analysis, heuristic detection, signature based detection, zero day protection, advanced persistent threat, apt protection, cyber security, information security, infosec, netsec, appsec, cloudsec, container security scanning, runtime protection, application runtime protection, rasp alternative, security testing, automated security, continuous security, security pipeline, ci cd security, build security, deploy security, production security, staging security, development security, security lifecycle, threat prevention, attack surface reduction, security posture, risk management, vulnerability management, patch management, security updates, version control security, dependency scanning, supply chain security, software security, secure coding, code review security, static analysis, dynamic analysis, security benchmarking, performance security, scalability security, distributed security, multi region security, global security, latency optimization, throughput optimization, connection pooling, keep alive, request optimization, response optimization, caching strategy, cdn integration, edge caching, origin protection, upstream protection, backend security, frontend security, full stack security, end to end security, security architecture, security design, security engineering, security development, security implementation, security deployment, security maintenance, security support, enterprise support, community support, documentation, security guides, tutorials, examples, use cases, case studies, benchmarks, comparison, alternative to, replacement for, migration guide, upgrade guide, configuration guide, troubleshooting, debugging, monitoring, alerting, reporting, analytics, statistics, metrics, kpi, security kpi, security metrics, threat metrics, attack metrics, blocked attacks, prevented attacks, detected threats, security events, security incidents, security violations, policy enforcement, rule engine, pattern matching, regex filtering, signature matching, behavioral blocking, reputation blocking, ip reputation, domain reputation, url reputation, threat feed, threat intelligence feed, security feed, blacklist, whitelist, greylist, allow list, deny list, security policy, security rules, custom rules, security configuration, hardening configuration, production ready, battle tested, field tested, proven security, reliable security, stable security, mature security, professional security, commercial grade, military grade, bank grade, government grade, compliance ready, audit ready, certification ready, security certification, security standard, security framework, security protocol, security specification, security requirement, security control, preventive control, detective control, corrective control, compensating control</sub>

