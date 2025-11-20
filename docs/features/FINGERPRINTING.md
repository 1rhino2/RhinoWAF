# Browser Fingerprinting Documentation

RhinoWAF's browser fingerprinting system detects bot networks, credential stuffing, and sophisticated attacks by tracking unique browser characteristics.

**Status**: **ENABLED by default in production** | **Version**: 2.0 | **Last Updated**: October 20, 2025

## Overview

Browser fingerprinting creates a unique identifier for each browser/device combination by collecting multiple characteristics that automated tools often fail to replicate correctly.

### What It Detects

- **Bot Networks**: Multiple IPs using the same browser/device
- **Credential Stuffing**: Rotating IPs but same fingerprint
- **Web Scrapers**: User-Agent rotation but consistent browser engine
- **Headless Browsers**: Missing canvas/WebGL data (Puppeteer, Selenium, Playwright)
- **Suspicious Patterns**: Too many IPs sharing identical fingerprints

## Configuration

### Production Defaults

**Enabled by default** in `cmd/rhinowaf/main.go`:

```go
fingerprintConfig := fingerprint.Config{
    Enabled:              true,  // ✓ ENABLED by default
    MaxIPsPerFingerprint: 5,     // Max IPs per fingerprint before blocking
    MaxAgeForReuse:       24 * time.Hour,
    SuspiciousThreshold:  3,     // Flag as suspicious at 3+ IPs
    BlockOnExceed:        true,  // Block when MaxIPsPerFingerprint exceeded
    RequireClientData:    true,  // Require canvas/WebGL (blocks headless browsers)
}
```

**To customize:** Edit `cmd/rhinowaf/main.go` and rebuild.

### Configuration Options

- **`Enabled`** (bool): Master switch for fingerprinting
- **`MaxIPsPerFingerprint`** (int): Maximum IPs allowed per fingerprint before blocking
  - Recommended: 3-10 for high security, 10-20 for normal use
- **`MaxAgeForReuse`** (time.Duration): How long a fingerprint is valid
  - Recommended: 24-72 hours
- **`SuspiciousThreshold`** (int): Flag fingerprints as suspicious when X IPs share it
  - Recommended: 2-5
- **`BlockOnExceed`** (bool): Block requests when MaxIPsPerFingerprint exceeded
  - `true`: Block automatically (recommended for production)
  - `false`: Log only (useful for testing)
- **`RequireClientData`** (bool): Require canvas/WebGL data
  - `true`: Blocks headless browsers (recommended)
  - `false`: Allow requests without client data

## How It Works

### Collection Process

1. **First Request**: User visits site without fingerprint cookie
2. **Challenge Page**: 1-2 second "Security Verification" page shown
3. **JavaScript Collects Data**:
   - Canvas fingerprint (unique rendering signature)
   - WebGL fingerprint (GPU vendor and renderer)
   - Font list (via canvas text measurement)
   - Screen resolution and color depth
   - CPU cores (navigator.hardwareConcurrency)
   - Device memory (navigator.deviceMemory)
   - Timezone and language
   - Platform and user agent
4. **Hash Created**: SHA-256 hash of all collected data
5. **Cookie Set**: Fingerprint stored in cookie (24-hour expiry)
6. **Subsequent Visits**: Cookie present → Instant access

### Data Points Collected

#### Canvas Fingerprint
```javascript
// Unique rendering signature based on:
- Text rendering (font smoothing, subpixel rendering)
- Emoji rendering (different across OS/browsers)
- Geometric shapes (anti-aliasing differences)
- Color blending modes
```

#### WebGL Fingerprint
```javascript
// GPU-specific information:
- WEBGL_VENDOR: GPU vendor (e.g., "Google Inc. (NVIDIA)")
- WEBGL_RENDERER: GPU model (e.g., "ANGLE (NVIDIA GeForce GTX 1080)")
- WEBGL_VERSION: WebGL version
- Supported extensions (30+ extensions unique per GPU)
```

#### System Information
```javascript
// Hardware/software characteristics:
- Screen: width, height, color depth, pixel ratio
- CPU: navigator.hardwareConcurrency (core count)
- Memory: navigator.deviceMemory (GB)
- Timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
- Language: navigator.language and navigator.languages
- Platform: navigator.platform
- User-Agent: Full UA string
```

#### Font Detection
```javascript
// Installed fonts detected via canvas measurement:
- Common fonts: Arial, Times, Courier, etc.
- System fonts: varies by OS
- Measurement technique: Text width comparison
```

### Fingerprint Hash

All data points are concatenated and hashed:

```javascript
const data = [
    canvasFingerprint,
    webglVendor,
    webglRenderer,
    fonts.join(','),
    screen.width,
    screen.height,
    navigator.hardwareConcurrency,
    // ... all other data points
].join('|');

const hash = sha256(data);  // 64-character hex string
```

## Endpoints

### POST /fingerprint/collect

Receives fingerprint data from client JavaScript.

**Request:**
```json
{
  "canvas": "a3f2b9c1...",
  "webgl_vendor": "Google Inc. (NVIDIA)",
  "webgl_renderer": "ANGLE (NVIDIA GeForce GTX 1080)",
  "fonts": ["Arial", "Times", "Courier", ...],
  "screen_width": 1920,
  "screen_height": 1080,
  "cpu_cores": 8,
  "device_memory": 16,
  "timezone": "America/New_York",
  "language": "en-US",
  "platform": "Win32",
  "user_agent": "Mozilla/5.0..."
}
```

**Response:**
```json
{
  "success": true,
  "fingerprint": "a3f2b9c1d4e5f6a7..."
}
```

Sets cookie: `rhinowaf_fp=<hash>; HttpOnly; SameSite=Lax; Max-Age=86400`

### GET /fingerprint/stats

Returns fingerprint tracking statistics.

**Response:**
```json
{
  "total_fingerprints": 1247,
  "suspicious_count": 3,
  "blocked_count": 1,
  "total_ips_tracked": 5832,
  "most_shared_fingerprint": {
    "hash": "a3f2b9c1...",
    "ip_count": 8,
    "is_suspicious": true,
    "is_blocked": true
  }
}
```

## Bot Detection

### Bot Network Detection

When multiple IPs share the same fingerprint:

1. **3+ IPs** (SuspiciousThreshold): Fingerprint flagged as suspicious
2. **5+ IPs** (MaxIPsPerFingerprint): Additional IPs blocked
3. **Logged**: All attempts logged with fingerprint hash and IP list

**Example scenario:**
- Botnet using 100 IPs with same browser
- First 5 IPs: Allowed through (building fingerprint data)
- 6th IP: Blocked (MaxIPsPerFingerprint exceeded)
- Logs show: "Blocked: Fingerprint a3f2b9c1... used by 6 IPs"

### Headless Browser Detection

Headless browsers (Puppeteer, Selenium) often fail to provide:
- Valid canvas fingerprints (empty or generic)
- WebGL data (missing vendor/renderer)
- Complete font lists

When `RequireClientData: true`:
- Missing canvas: Blocked
- Missing WebGL: Blocked
- Empty font list: Blocked

**Common headless indicators:**
```javascript
// Puppeteer default:
navigator.webdriver = true  // Detectable

// Missing APIs:
navigator.mediaDevices = undefined
navigator.permissions = undefined

// Generic canvas rendering:
canvas fingerprint = same generic value across IPs
```

## Monitoring

### Real-Time Stats

```bash
# Get current statistics
curl http://localhost:8080/fingerprint/stats | jq

# Monitor suspicious activity
watch -n 5 'curl -s http://localhost:8080/fingerprint/stats | jq ".suspicious_count"'
```

### Log Analysis

Fingerprint events are logged to `./logs/ddos.log`:

```json
{
  "timestamp": "2025-10-20T14:30:00Z",
  "event_type": "fingerprint_blocked",
  "ip": "203.0.113.42",
  "fingerprint": "a3f2b9c1d4e5f6a7...",
  "reason": "MaxIPsPerFingerprint exceeded (6 IPs)",
  "severity": "high",
  "recommended_action": "Ban fingerprint or investigate bot network"
}
```

### Analyzing Patterns

```bash
# Find most reused fingerprints
jq -r 'select(.event_type == "fingerprint_suspicious") | .fingerprint' logs/ddos.log | sort | uniq -c | sort -nr

# Count blocked fingerprints
jq -r 'select(.event_type == "fingerprint_blocked")' logs/ddos.log | wc -l

# Find IPs sharing suspicious fingerprints
jq -r 'select(.event_type == "fingerprint_suspicious") | "\(.fingerprint) - \(.ip)"' logs/ddos.log
```

## Security Considerations

### Privacy

- **No personal data**: Only technical characteristics collected
- **No tracking across sites**: Fingerprint unique to RhinoWAF domain
- **Cookies only**: HttpOnly, SameSite=Lax for security
- **24-hour expiry**: Fingerprints expire and must be recollected

### False Positives

**Shared fingerprints can occur legitimately:**

1. **Corporate Networks**: Identical SOE (Standard Operating Environment)
   - Same OS, browser, screen resolution
   - Solution: Whitelist corporate IP ranges

2. **Public WiFi**: Library/cafe computers
   - Shared hardware and software
   - Solution: Increase MaxIPsPerFingerprint (10-20)

3. **VM Farms**: Cloud desktops (Citrix, VMware Horizon)
   - Identical virtual hardware
   - Solution: Whitelist known VM providers

4. **Embedded Browsers**: Mobile apps using WebView
   - Limited fingerprint entropy
   - Solution: Reduce RequireClientData strictness

### Evasion Techniques

**Sophisticated attackers may:**

1. **Randomize canvas**: Add noise to canvas rendering
   - Mitigation: Require WebGL + fonts + hardware data

2. **Rotate fingerprints**: Generate new fingerprint per IP
   - Mitigation: Lowers throughput, costs increase

3. **Use real browsers**: Residential proxy + real Chrome
   - Mitigation: Combine with behavioral analysis, rate limiting

4. **Disable JavaScript**: Skip fingerprinting entirely
   - Mitigation: JavaScript challenges require JS execution

## Performance

### Impact

- **First visit**: +1-2 seconds (fingerprint collection page)
- **Subsequent visits**: +5ms (cookie validation)
- **Memory**: ~1KB per fingerprint
- **CPU**: Minimal (hash lookups only)

### Optimization

```go
// For high-traffic sites:
fingerprintConfig := fingerprint.Config{
    MaxAgeForReuse:       72 * time.Hour,  // Longer expiry
    SuspiciousThreshold:  10,               // More lenient
    MaxIPsPerFingerprint: 20,               // Allow more IPs
    RequireClientData:    false,            // Faster collection
}
```

### Scaling

- **In-memory storage**: Suitable for single server or low traffic
- **Redis backend** (planned): For multi-server deployments
- **Cleanup**: Automatic expiry of old fingerprints
- **Limits**: Can track millions of fingerprints efficiently

## Best Practices

### For Public Websites
```go
fingerprintConfig := fingerprint.Config{
    Enabled:              true,
    MaxIPsPerFingerprint: 10,   // Moderate
    SuspiciousThreshold:  5,    // Lenient
    RequireClientData:    true,
}
```

### For E-commerce
```go
fingerprintConfig := fingerprint.Config{
    Enabled:              true,
    MaxIPsPerFingerprint: 5,    // Strict
    SuspiciousThreshold:  3,    // Moderate
    RequireClientData:    true,
    BlockOnExceed:        true,  // Prevent fraud
}
```

### For APIs
```go
fingerprintConfig := fingerprint.Config{
    Enabled:              false,  // Not browser-based
    // Use token authentication instead
}
```

### For High-Security
```go
fingerprintConfig := fingerprint.Config{
    Enabled:              true,
    MaxIPsPerFingerprint: 3,     // Very strict
    SuspiciousThreshold:  2,     // Flag quickly
    RequireClientData:    true,
    BlockOnExceed:        true,
    MaxAgeForReuse:       12 * time.Hour,  // Shorter expiry
}
```

## Testing

### Test Collection

```bash
# Visit site in browser
curl -v http://localhost:8080/

# Should redirect to fingerprint collection page
# Complete in browser to set cookie

# Subsequent requests should pass
curl -v http://localhost:8080/ -b cookies.txt -c cookies.txt
```

### Test Statistics

```bash
# Check stats
curl http://localhost:8080/fingerprint/stats

# Should show:
# {
#   "total_fingerprints": 1,
#   "suspicious_count": 0,
#   "blocked_count": 0,
#   ...
# }
```

### Test Bot Detection

```bash
# Simulate bot network (requires manual fingerprint injection)
# Use multiple IPs with same fingerprint hash
# After MaxIPsPerFingerprint exceeded, should see blocks in logs
```

## Troubleshooting

### Issue: Too many false positives

**Solution**: Increase thresholds
```go
MaxIPsPerFingerprint: 20,  // Allow more IPs
SuspiciousThreshold:  10,  // Less aggressive flagging
```

### Issue: Legitimate users blocked

**Solution**: Whitelist IP ranges
```json
// In ip_rules.json
"whitelisted_ips": [
  { "ip": "10.0.0.0/8", "reason": "Corporate network" }
]
```

### Issue: Headless browsers needed (testing)

**Solution**: Disable client data requirement
```go
RequireClientData: false,  // Allow headless
```

### Issue: Performance impact

**Solution**: Optimize collection
```go
MaxAgeForReuse: 72 * time.Hour,  // Longer expiry = less collection
```

## See Also

- **CHALLENGE_SYSTEM.md** - Challenge system integration
- **IP_RULES.md** - IP whitelisting and rules
- **FINGERPRINTING_EXAMPLES.md** - Configuration examples
- **PRODUCTION_CONFIG.md** - Production deployment guide

---

**Status**: ✅ Production-Ready | **Version**: 2.0 | **Last Updated**: October 20, 2025
