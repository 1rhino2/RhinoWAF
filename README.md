# RhinoWAF

Web Application Firewall in Go with DDoS protection, input sanitization, and attack logging.

## Features

- DDoS protection with rate limiting, burst detection, and IP reputation
- Slowloris detection and mitigation
- Input sanitization for SQL injection, XSS, and malicious payloads
- JSON attack logging with detailed metrics
- IP management (ban/whitelist/monitor)
- Adaptive throttling under attack

## Quick Start

```bash
go run cmd/rhinowaf/main.go
```

Server starts on `:8080`. Logs written to `./logs/ddos.log`.

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

Config file at `./config/ip_rules.json`:

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

Usage:

```go
ipm := ddos.GetIPManager()
ipm.BanIP("203.0.113.42", "brute force", "admin", 24*time.Hour, nil)
ipm.WhitelistIP("10.0.0.1", "internal", "devops", "", nil)
ipm.MonitorIP("198.51.100.42", "suspicious", nil)
```

## License

AGPL-3.0 - requires open sourcing derivative works

