# HTTP Request Smuggling Detection

**Status**: Production (v2.4.0)  
**Module**: `waf/smuggling`  
**Integration**: Automatic in `AdaptiveProtect` middleware

## Overview

RhinoWAF v2.4.0 introduces comprehensive HTTP request smuggling detection to prevent CL.TE, TE.CL, and other smuggling-based attacks. The system detects conflicting headers, obfuscation attempts, and protocol violations before requests reach the backend.

## What is HTTP Request Smuggling?

Request smuggling exploits inconsistencies in how frontend (proxy/CDN) and backend servers parse HTTP requests. Attackers craft requests that are interpreted differently by each layer, allowing malicious requests to "smuggle" through security controls.

### Common Attack Vectors

**CL.TE (Content-Length + Transfer-Encoding)**
- Frontend uses Content-Length, backend uses Transfer-Encoding
- Allows attacker to append additional request to the stream

**TE.CL (Transfer-Encoding + Content-Length)**
- Frontend uses Transfer-Encoding, backend uses Content-Length
- Enables request splitting and backend poisoning

**TE.TE (Dual Transfer-Encoding)**
- Multiple Transfer-Encoding headers or obfuscated values
- Exploits parsing differences between systems

## Detection Capabilities

### Violation Types

| Type | Severity | Description |
|------|----------|-------------|
| `CL_TE_CONFLICT` | 5 | Both Content-Length and chunked Transfer-Encoding present |
| `TE_CL_CONFLICT` | 5 | Transfer-Encoding present with Content-Length |
| `MULTIPLE_CL` | 5 | Multiple Content-Length headers detected |
| `MULTIPLE_TE` | 5 | Multiple conflicting Transfer-Encoding headers |
| `DUPLICATE_TE` | 4 | Duplicate identical Transfer-Encoding headers |
| `INVALID_CL` | 5 | Non-numeric or malformed Content-Length value |
| `INVALID_TE` | 4 | Invalid Transfer-Encoding value (not chunked/gzip/etc) |
| `OBFUSCATED_CL` | 5 | Whitespace, hex, or obfuscation in Content-Length |
| `OBFUSCATED_TE` | 5 | Whitespace or obfuscation in Transfer-Encoding |
| `WHITESPACE_IN_CL` | 5 | Control characters in Content-Length header |
| `WHITESPACE_IN_TE` | 5 | Control characters in Transfer-Encoding header |
| `CONFLICTING_TE` | 5 | Multiple "chunked" in single Transfer-Encoding header |
| `CL_ZERO_WITH_TE` | 4 | Content-Length: 0 combined with Transfer-Encoding |
| `NEGATIVE_CL` | 5 | Negative Content-Length value |
| `HTTP09_WITH_HEADERS` | 5 | HTTP/0.9 request with headers (rare vector) |
| `INVALID_PROTOCOL` | 4 | Invalid HTTP protocol version |

### Severity Levels

- **5 (Critical)**: Definite smuggling attempt, blocks immediately
- **4 (High)**: Suspicious pattern, blocked by default
- **3 (Medium)**: Potential issue, logged but not blocked
- **2 (Low)**: Minor anomaly, logged for analysis
- **1 (Info)**: Informational, tracking only

## Configuration

### Default Settings (v2.4.0)

```go
smugglingDetector = smuggling.NewDetector(
    true,  // EnableStrictMode - validate all headers strictly
    true,  // LogViolations - log all violations regardless of severity
    4,     // BlockOnSeverity - block if severity >= 4
)
```

### Adjusting Detection Sensitivity

**Strict Mode (Recommended for Production)**
```go
detector := smuggling.NewDetector(true, true, 4)
```
- Blocks severity 4+ violations (high/critical)
- Logs all violations for monitoring
- Detects obfuscation and edge cases

**Moderate Mode**
```go
detector := smuggling.NewDetector(false, true, 5)
```
- Only blocks severity 5 (critical) violations
- Still logs all violations
- Allows some edge cases through

**Permissive Mode (Testing Only)**
```go
detector := smuggling.NewDetector(false, true, 6)
```
- Logs violations but doesn't block
- Useful for testing legitimate traffic patterns

## Integration

### Automatic Protection

Smuggling detection runs automatically in `AdaptiveProtect` middleware:

```go
func AdaptiveProtect(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        ip := ddos.GetIP(r)

        // Check for HTTP request smuggling attempts
        if violations, shouldBlock := smugglingDetector.Check(r); len(violations) > 0 {
            for _, v := range violations {
                metrics.SmugglingViolationsDetected.WithLabelValues(
                    string(v.Type),
                    fmt.Sprintf("%d", v.Severity),
                ).Inc()

                if shouldBlock {
                    metrics.SmugglingAttemptsBlocked.WithLabelValues(string(v.Type)).Inc()
                }
            }

            if shouldBlock {
                summary := smuggling.GetViolationSummary(violations)
                templates.RenderBlockedError(w, ip, "HTTP request smuggling detected: "+summary)
                return
            }
        }

        // Continue to other security checks...
    }
}
```

### Execution Order

1. **Smuggling Detection** ← First line of defense
2. Header Validation (sanitize)
3. IP Rules (ddos)
4. Rate Limiting (ddos)
5. Malicious Input Detection (sanitize)
6. Input Sanitization (sanitize)
7. Backend Proxy

## Monitoring

### Prometheus Metrics

**Blocked Attempts**
```
rhinowaf_smuggling_attempts_blocked_total{violation_type}
```
Tracks smuggling attempts that were blocked, labeled by violation type.

**All Violations Detected**
```
rhinowaf_smuggling_violations_detected_total{violation_type,severity}
```
Tracks all violations including non-blocking ones for analysis.

### Example Queries

**Top Smuggling Attack Types**
```promql
topk(5, rate(rhinowaf_smuggling_attempts_blocked_total[5m]))
```

**Severity Distribution**
```promql
sum by(severity) (rate(rhinowaf_smuggling_violations_detected_total[1h]))
```

**Attack Rate by IP** (requires custom labeling)
```promql
sum by(client_ip) (rate(rhinowaf_smuggling_attempts_blocked_total[5m])) > 0
```

## Attack Examples

### CL.TE Attack

**Malicious Request**
```http
POST / HTTP/1.1
Host: vulnerable.example.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

**Detection**
- Violation: `CL_TE_CONFLICT` (severity 5)
- Reason: Both Content-Length and Transfer-Encoding: chunked present
- Action: Blocked immediately

### TE.CL Attack

**Malicious Request**
```http
POST / HTTP/1.1
Host: vulnerable.example.com
Transfer-Encoding: chunked
Content-Length: 4

5c
GET /admin HTTP/1.1
Host: vulnerable.example.com

0


```

**Detection**
- Violation: `TE_CL_CONFLICT` (severity 5)
- Reason: Transfer-Encoding with Content-Length present
- Action: Blocked immediately

### Obfuscated Headers

**Malicious Request**
```http
POST / HTTP/1.1
Host: vulnerable.example.com
Content-Length: 0x10
Transfer-Encoding: chunked

[request body]
```

**Detection**
- Violation: `OBFUSCATED_CL` (severity 5)
- Reason: Hex-encoded Content-Length value
- Action: Blocked immediately

### Multiple Content-Length

**Malicious Request**
```http
POST / HTTP/1.1
Host: vulnerable.example.com
Content-Length: 6
Content-Length: 0

[smuggled request]
```

**Detection**
- Violation: `MULTIPLE_CL` (severity 5)
- Reason: Multiple Content-Length headers detected
- Action: Blocked immediately

## False Positives

### Legitimate Scenarios

Some legitimate proxies or clients may trigger low-severity violations:

1. **Duplicate Identical Headers** (severity 4)
   - Some proxies duplicate Transfer-Encoding unintentionally
   - Consider whitelisting known proxy IPs if this occurs frequently

2. **CL:0 with TE** (severity 4)
   - Rare but valid for some chunked uploads with initial empty body
   - Adjust blocking threshold to 5 if needed

### Whitelisting

To whitelist specific IPs from smuggling detection:

```json
{
  "rules": [
    {
      "ip": "192.168.1.100",
      "type": "whitelist",
      "reason": "Internal proxy with duplicate headers",
      "priority": 100
    }
  ]
}
```

Whitelisted IPs bypass all WAF checks including smuggling detection.

## Testing

### Test Smuggling Detection

**Test CL.TE Attack**
```bash
curl -X POST http://localhost:8080/ \
  -H "Content-Length: 6" \
  -H "Transfer-Encoding: chunked" \
  -d "test"
```

**Expected Response**
```
HTTP request smuggling detected: CL_TE_CONFLICT (severity: 5)
```

**Test Multiple Headers**
```bash
curl -X POST http://localhost:8080/ \
  -H "Content-Length: 10" \
  -H "Content-Length: 20" \
  -d "testdata"
```

**Expected Response**
```
HTTP request smuggling detected: MULTIPLE_CL (severity: 5)
```

### Verify Metrics

```bash
curl http://localhost:8080/metrics | grep smuggling
```

**Expected Output**
```
rhinowaf_smuggling_attempts_blocked_total{violation_type="CL_TE_CONFLICT"} 5
rhinowaf_smuggling_violations_detected_total{severity="5",violation_type="CL_TE_CONFLICT"} 5
```

## Security Best Practices

### Layered Defense

Smuggling detection is one layer of protection. Always combine with:

1. **IP Rules**: Block known malicious IPs/ASNs
2. **Rate Limiting**: Prevent repeated smuggling attempts
3. **Reputation Checks**: Flag IPs attempting smuggling
4. **Challenge System**: Force attackers to prove legitimacy
5. **Input Sanitization**: Remove malicious patterns post-detection

### Logging

All smuggling violations are logged regardless of blocking:

```json
{
  "timestamp": "2025-12-01T10:30:00Z",
  "event_type": "smuggling_violation",
  "severity": 5,
  "ip": "192.168.1.100",
  "violation_type": "CL_TE_CONFLICT",
  "description": "CL.TE smuggling detected: CL=6, TE=chunked",
  "headers": {
    "Content-Length": ["6"],
    "Transfer-Encoding": ["chunked"]
  },
  "action": "blocked"
}
```

### Alerting

Configure webhook notifications for critical smuggling attempts:

```json
{
  "webhook_urls": ["https://hooks.slack.com/services/YOUR/WEBHOOK/URL"],
  "min_severity": "critical",
  "events": ["smuggling_violation"]
}
```

## Performance Impact

- **Detection Overhead**: <0.5ms per request
- **Memory Usage**: Minimal (pre-compiled regexes)
- **CPU Impact**: Negligible for typical traffic
- **Throughput**: No measurable impact on benchmarks

## Troubleshooting

### High False Positive Rate

**Symptom**: Legitimate requests being blocked

**Solutions**:
1. Check violation types in metrics
2. Adjust blocking threshold from 4 to 5
3. Whitelist known proxies/CDNs
4. Review logs for specific patterns

### Missing Detections

**Symptom**: Smuggling attacks not detected

**Solutions**:
1. Ensure strict mode is enabled
2. Verify detector initialization in `adaptive.go`
3. Check blocking threshold isn't too high (>5)
4. Review attack pattern against supported violations

### Performance Degradation

**Symptom**: Slow request processing

**Solutions**:
1. Verify no regex backtracking issues
2. Check if logging is overwhelming disk I/O
3. Consider disabling low-severity violation logging
4. Profile with pprof to identify bottlenecks

## Future Enhancements

Planned for v2.5+:

- **Custom Violation Rules**: User-defined smuggling patterns
- **ML-Based Detection**: Anomaly detection for novel attacks
- **Response Smuggling**: Detect smuggling in backend responses
- **Detailed Logging**: Per-violation structured logs with full request context
- **Auto-Ban**: Automatically ban IPs after N smuggling attempts

## References

- [HTTP Request Smuggling - PortSwigger](https://portswigger.net/web-security/request-smuggling)
- [RFC 7230 - HTTP/1.1 Message Syntax](https://tools.ietf.org/html/rfc7230)
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)

## Version History

- **v2.4.0** (December 2025) - Initial release with 17 violation types
- **v2.4.1** (Planned) - Custom violation rules and ML detection
