# Fingerprinting Configuration Examples

## Example 1: Basic Bot Detection

Detect bot networks sharing the same fingerprint across multiple IPs.

```go
fingerprintConfig := fingerprint.Config{
    Enabled:              true,
    MaxIPsPerFingerprint: 5,     // Allow up to 5 IPs per fingerprint
    MaxAgeForReuse:       24 * time.Hour,
    SuspiciousThreshold:  3,     // Flag when 3+ IPs share fingerprint
    BlockOnExceed:        false, // Don't block yet, just flag
    RequireClientData:    false, // Allow requests without canvas data
}
```

**Use case:** Monitor bot activity without blocking legitimate users (corporate networks, VPNs).

---

## Example 2: Strict Credential Stuffing Protection

Prevent credential stuffing attacks where attackers rotate IPs but use same browser.

```go
fingerprintConfig := fingerprint.Config{
    Enabled:              true,
    MaxIPsPerFingerprint: 2,     // Very strict: max 2 IPs per fingerprint
    MaxAgeForReuse:       12 * time.Hour, // Short validity window
    SuspiciousThreshold:  2,     // Flag immediately at 2 IPs
    BlockOnExceed:        true,  // Block when exceeded
    RequireClientData:    true,  // Require canvas/WebGL (blocks headless)
}
```

**Use case:** Protect `/login`, `/register`, `/password-reset` endpoints.

---

## Example 3: Headless Browser Blocking

Block automated browsers (Puppeteer, Selenium, PhantomJS) that lack proper fingerprints.

```go
fingerprintConfig := fingerprint.Config{
    Enabled:              true,
    MaxIPsPerFingerprint: 10,    // Lenient on IP count
    MaxAgeForReuse:       48 * time.Hour,
    SuspiciousThreshold:  5,     
    BlockOnExceed:        false, 
    RequireClientData:    true,  // KEY: Require canvas/WebGL data
}
```

**Use case:** Block scraping bots while allowing legitimate traffic. Headless browsers often fail canvas/WebGL collection.

---

## Example 4: Corporate Network Friendly

Allow shared fingerprints for corporate environments (Citrix, VDI, shared VPN).

```go
fingerprintConfig := fingerprint.Config{
    Enabled:              true,
    MaxIPsPerFingerprint: 50,    // Very lenient for corporate networks
    MaxAgeForReuse:       7 * 24 * time.Hour, // 1 week
    SuspiciousThreshold:  20,    // High threshold
    BlockOnExceed:        false, // Never block based on IP count
    RequireClientData:    false, // Don't require for compatibility
}
```

**Use case:** B2B applications where many employees share similar setups.

---

## Example 5: Combined with Challenge System

Use fingerprinting to identify suspicious traffic, then challenge them.

```go
// Setup fingerprinting (lenient)
fingerprintConfig := fingerprint.Config{
    Enabled:              true,
    MaxIPsPerFingerprint: 5,
    SuspiciousThreshold:  3,
    BlockOnExceed:        false, // Don't block, challenge instead
}
fingerprintTracker := fingerprint.NewTracker(fingerprintConfig)

// Setup challenges (strict)
challengeConfig := challenge.Config{
    Enabled:     true,
    DefaultType: challenge.TypeHCaptcha,
}

// Custom middleware: Challenge suspicious fingerprints
func smartProtection(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        cookie, _ := r.Cookie("waf_fingerprint")
        if cookie != nil && fingerprintTracker.IsSuspicious(cookie.Value) {
            // Suspicious fingerprint → Force CAPTCHA
            challengeMW.RequireChallenge(w, r)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

**Use case:** Best of both worlds - fingerprint identifies bad actors, challenges verify them.

---

## Example 6: API Protection (No Browser)

For APIs that don't have browsers, use server-side fingerprinting only.

```go
fingerprintConfig := fingerprint.Config{
    Enabled:              true,
    MaxIPsPerFingerprint: 3,
    MaxAgeForReuse:       1 * time.Hour, // Short for APIs
    SuspiciousThreshold:  2,
    BlockOnExceed:        true,
    RequireClientData:    false, // APIs don't have canvas/WebGL
}
```

**Use case:** REST APIs where client-side JavaScript isn't available. Uses User-Agent, Accept headers, etc.

---

## Example 7: High-Security Mode

Maximum protection for critical endpoints (admin panels, payments).

```go
fingerprintConfig := fingerprint.Config{
    Enabled:              true,
    MaxIPsPerFingerprint: 1,     // Each fingerprint = 1 IP only
    MaxAgeForReuse:       6 * time.Hour,
    SuspiciousThreshold:  1,     // Flag everything that reuses fingerprints
    BlockOnExceed:        true,  // Block immediately
    RequireClientData:    true,  // Must have full browser data
}
```

**Use case:** `/admin/*`, `/payment/*`, `/account/settings/*` - zero tolerance for shared fingerprints.

---

## Monitoring & Debugging

### Check Statistics

```bash
curl http://localhost:8080/fingerprint/stats | jq .
```

Response:
```json
{
  "total_fingerprints": 523,
  "suspicious_fingerprints": 12,
  "blocked_fingerprints": 3,
  "average_ips_per_print": 1.4,
  "top_fingerprints": [
    {
      "hash": "abc123def456...",
      "ip_count": 8,
      "last_seen": "2025-10-19T15:30:00Z",
      "suspicious": true
    }
  ]
}
```

### Enable Logging

Add logging to see what's being detected:

```go
fingerprintTracker := fingerprint.NewTracker(fingerprintConfig)

// Wrap Track() to log
originalTrack := fingerprintTracker.Track
fingerprintTracker.Track = func(ip string, fp *fingerprint.Fingerprint) error {
    err := originalTrack(ip, fp)
    if err != nil {
        log.Printf("[FINGERPRINT] Blocked %s: %v", ip, err)
    } else {
        log.Printf("[FINGERPRINT] Tracked %s: %s (IPs: %d)", 
            ip, fp.Hash[:8], len(fp.IPs))
    }
    return err
}
```

### Test Locally

```bash
# Enable fingerprinting in code
sed -i 's/Enabled:              false/Enabled:              true/' cmd/rhinowaf/main.go

# Build
go build -o rhinowaf ./cmd/rhinowaf/

# Run
./rhinowaf

# Open browser
google-chrome http://localhost:8080

# Should see "Security Verification" page for 1-2 seconds
# Then check console (F12):
# - Should see fingerprint POST to /fingerprint/collect
# - Cookie "waf_fingerprint" should be set

# Check stats
curl http://localhost:8080/fingerprint/stats
```

---

## Configuration Decision Matrix

| Scenario | MaxIPs | RequireClientData | BlockOnExceed | Recommended |
|----------|--------|-------------------|---------------|-------------|
| Public website | 10 | false | false | Monitor only |
| E-commerce | 5 | true | true | Balanced |
| Login pages | 2 | true | true | Strict |
| Admin panel | 1 | true | true | Maximum |
| API endpoint | 3 | false | true | API mode |
| Corporate B2B | 50 | false | false | Lenient |

---

## Troubleshooting

### Users Complain of "Access Denied"

**Problem:** Legitimate users being blocked.

**Solution:**
1. Increase `MaxIPsPerFingerprint` from 5 to 10-20
2. Set `BlockOnExceed: false` to only flag, not block
3. Check if corporate VPN/proxy causing shared fingerprints

### Bots Still Getting Through

**Problem:** Sophisticated bots bypassing fingerprinting.

**Solution:**
1. Set `RequireClientData: true` to block headless browsers
2. Lower `SuspiciousThreshold` to 2
3. Combine with challenge system (hCaptcha/Turnstile)
4. Enable additional bot detection (User-Agent checks)

### Performance Issues

**Problem:** Server memory growing, slow responses.

**Solution:**
1. Lower `MaxAgeForReuse` from 24h to 6-12h
2. Monitor memory: `curl /fingerprint/stats | jq .total_fingerprints`
3. Consider Redis backend for distributed tracking (future feature)

### Fingerprint Page Loops Infinitely

**Problem:** Collection page keeps refreshing.

**Solution:**
1. Check browser console for JavaScript errors
2. Disable `RequireClientData` temporarily
3. Whitelist `/fingerprint/collect` in challenge system
4. Check for CORS issues if behind proxy

---

## Privacy & Compliance

### GDPR Compliance

- Fingerprints are **hashed** (SHA-256) - not reversible to personal data
- Cookie consent: Inform users about fingerprint cookies
- Data retention: Use short `MaxAgeForReuse` (12-24h)
- Right to access: Provide endpoint to show user their fingerprint
- Right to erasure: Delete fingerprint on request

### Privacy Best Practices

1. **Don't link to PII:** Never associate fingerprints with names, emails
2. **Short retention:** Use 12-24h `MaxAgeForReuse`, not permanent
3. **Transparency:** Document fingerprinting in privacy policy
4. **Opt-out option:** Allow users to disable fingerprinting (reduced functionality)
5. **Secure storage:** Hashes only, never store raw canvas/WebGL data

---

## Performance Benchmarks

**Memory Usage:**
- 1,000 fingerprints = ~1MB RAM
- 10,000 fingerprints = ~10MB RAM
- 100,000 fingerprints = ~100MB RAM

**CPU Impact:**
- Server-side hash: ~0.1ms per request
- Client-side collection: ~100-300ms (first visit only)
- Cookie verification: ~0.01ms per request

**Latency:**
- First visit: +100-300ms (client-side collection)
- Returning visits: +0.1ms (cookie check)
- No impact on API/JSON requests

---

For complete documentation, see [docs/FINGERPRINTING.md](../docs/FINGERPRINTING.md)
