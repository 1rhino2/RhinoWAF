# RhinoWAF

A Detailed Web Application Firewall (WAF) built in Go with adaptive protection against DDoS attacks, SQL injection, XSS, and other web threats.

## Features



- **DDoS Protection**:
  - Sliding window rate limiting for accurate tracking
  - IP reputation system to catch repeat offenders
  - Burst detection for instant blocking
  - Automatic memory cleanup to prevent leaks
  - Layer 4 and Layer 7 protection with adaptive thresholds
  - **Comprehensive Attack Logging**: JSON-formatted logs with 30+ data points per attack
- **Input Sanitization**: SQL injection, XSS, and malicious input filtering
- **Adaptive Middleware**: Combines all security features seamlessly
- **High Performance**: Fast RPS handling with modular architecture
- **Universal Protection**: Sanitizes URL params, form data, headers, and cookies
- **Production Ready Attack Forensics**: Detailed logging for compliance and analysis
- **NOW IT'S PRODUCTION READY! :D**

## Structure

```
RhinoWAF/
├── cmd/
│   └── rhinowaf/
│       └── main.go
├── handlers/
│   └── handlers.go
├── waf/
│   ├── adaptive.go
│   ├── ddos/
│   │   └── ddos.go
│   └── sanitize/
│       └── sanitize.go
├── go.mod
├── go.sum
└── README.md
```

## DDoS Attack Logging

RhinoWAF includes enterprise-grade attack logging that captures every DDoS attempt with forensic-level detail. All attacks are logged to `./logs/ddos.log` in JSON format for easy parsing and analysis.

### What Gets Logged

Every attack event includes **30+ data points**:
- **Attack Type**: rate_limit, burst, slowloris, reputation, l4_flood
- **Severity**: low, medium, high, critical (auto-calculated)
- **IP Information**: address, reputation score, violation history
- **Attack Metrics**: request/connection counts, rate limits exceeded, excess percentage
- **Timing Data**: first seen, last seen, block duration
- **Recommended Actions**: automated response suggestions based on severity

### Example Log Entries

**Burst Attack (Critical):**
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

**Rate Limit Violation (Medium):**
```json
{
  "timestamp": "2025-10-18T13:13:27Z",
  "event_type": "rate_limit",
  "ip": "192.168.1.100",
  "severity": "medium",
  "request_count": 81,
  "rate_limit": 80,
  "excess_percentage": 1,
  "reputation": 34,
  "message": "L7 rate limit exceeded: 81/80 requests (1% over limit)",
  "recommended_action": "STANDARD_BLOCK - Temporary block, monitor for repeat offense"
}
```

### Log File Location

By default, logs are written to `./logs/ddos.log` relative to where the server is started. The logger automatically:
- Creates the log directory if it doesn't exist
- Appends to existing logs (no data loss on restart)
- Uses JSON Lines format (one JSON object per line)
- Supports log rotation for long-running deployments

### Configuration

The logger is initialized automatically with sensible defaults. For custom configuration:

```go
import "rhinowaf/waf/ddos"

config := &ddos.LoggerConfig{
    LogPath:      "/var/log/rhinowaf/ddos.log",  // Custom path
    Enabled:      true,                           // Enable/disable logging
    LogToConsole: false,                          // Also print to stdout
}
ddos.InitLogger(config)
```

### Analysis & Monitoring

Parse logs with any JSON tool:

```bash
# Count attacks by severity
cat logs/ddos.log | jq -r '.severity' | sort | uniq -c

# Find IPs with multiple violations
cat logs/ddos.log | jq -r 'select(.violation_count > 5) | .ip'

# Export to CSV for Excel analysis
cat logs/ddos.log | jq -r '[.timestamp, .ip, .severity, .event_type] | @csv'

# Real-time monitoring
tail -f logs/ddos.log | jq '.message'
```

## IP Rules (ban/whitelist/monitor) — Quick tutorial

RhinoWAF lets you manage IP access with a simple JSON file and a small API.

### 1) Config file location

- Default path: `./config/ip_rules.json`
- It contains three lists: `banned_ips`, `whitelisted_ips`, `monitored_ips`

Minimal example:

```json
{
  "version": "1.0",
  "last_modified": "2025-01-18T00:00:00Z",
  "banned_ips": [
    { "ip": "192.0.2.10", "type": "ban", "reason": "brute force", "expires_at": null }
  ],
  "whitelisted_ips": [
    { "ip": "10.0.0.1", "type": "whitelist", "reason": "internal monitoring" }
  ],
  "monitored_ips": [
    { "ip": "198.51.100.42", "type": "monitor", "reason": "suspicious traffic" }
  ]
}
```

Notes:

- `expires_at` can be RFC3339 timestamp or `null` (permanent ban)
- Whitelist bypasses all checks; bans block immediately; monitor adds extra logging


### 2) Initialize in your server

```go
import (
    "log"
    "rhinowaf/waf"
    "rhinowaf/waf/ddos"
)

func main() {
    // Load IP rules and auto-save on changes
    if err := ddos.InitIPManager("./config/ip_rules.json", true); err != nil {
        log.Fatal(err)
    }

    handler := waf.AdaptiveProtect(yourHandler)
    log.Fatal(http.ListenAndServe(":8080", handler))
}
```

### 3) Quick operations (code)

```go
ipm := ddos.GetIPManager()

// Ban for 24 hours
_ = ipm.BanIP("203.0.113.42", "brute force", "admin", 24*time.Hour, []string{"brute-force"})

// Permanent ban (duration 0)
_ = ipm.BanIP("198.51.100.25", "persistent attacker", "admin", 0, nil)

// Whitelist (bypasses all checks)
_ = ipm.WhitelistIP("10.0.0.1", "internal", "devops", "health checks", []string{"internal"})

// Monitor (extra logging)
_ = ipm.MonitorIP("198.51.100.42", "suspicious", []string{"watch"})

// Reload rules after manual JSON edit
_ = ipm.Reload()
```

Tip: expired temporary bans are cleaned up automatically every hour.

## Quick Start

- DDoS block (L7/L4)
- SQLi, XSS, encoding protection
- Universal input sanitizer
- Fast RPS, modular

Run:  
`go run cmd/rhinowaf/main.go`

## License

### AGPL-3.0 (Anti Skid)

This project is licensed under the GNU Affero General Public License v3.0, which means:

- Free to use and modify
- Open source contributions welcome
- **Skidders watch out!**: Any use (including web services) requires open sourcing your ENTIRE codebase
- Cannot be used in proprietary/closed-source applications

