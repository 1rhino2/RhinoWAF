# Challenge System Examples

Real-world examples and configuration patterns for the RhinoWAF challenge system.

## Example 1: Basic JavaScript Challenge

Blocks simple curl/wget attacks while allowing browsers.

```go
challengeConfig := challenge.Config{
    Enabled:     true,
    DefaultType: challenge.TypeJavaScript,
    Difficulty:  0,  // Not used for JS challenges
}
```

**Result:** Users see a 2-second "Verifying your browser..." page that auto-submits with JavaScript.

## Example 2: Admin Panel Protection

Require proof-of-work for all admin access.

```go
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeProofOfWork,
    Difficulty:      4,  // ~1-5 seconds on average CPU
    RequireForPaths: []string{"/admin/"},
    WhitelistPaths:  []string{"/admin/static/"},
}
```

**Result:** Admin routes show POW challenge, static assets load freely.

## Example 3: API Rate Limiting with POW

Make expensive API calls computationally expensive for clients.

```go
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeProofOfWork,
    Difficulty:      5,  // ~10-30 seconds
    RequireForPaths: []string{"/api/search", "/api/export"},
}
```

**Result:** Search/export APIs require solving hard puzzle before access.

## Example 4: hCaptcha for User Registration

Human verification for new account creation.

```go
// Set environment variables first
os.Setenv("HCAPTCHA_SITE_KEY", "10000000-ffff-ffff-ffff-000000000001")
os.Setenv("HCAPTCHA_SECRET", "0x0000000000000000000000000000000000000000")

challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeHCaptcha,
    RequireForPaths: []string{"/register", "/signup"},
}
```

**Result:** Registration routes show hCaptcha widget before proceeding.

## Example 5: Cloudflare Turnstile (Invisible)

Seamless bot protection with minimal user friction.

```go
os.Setenv("TURNSTILE_SITE_KEY", "1x00000000000000000000AA")
os.Setenv("TURNSTILE_SECRET", "1x0000000000000000000000000000000AA")

challengeConfig := challenge.Config{
    Enabled:     true,
    DefaultType: challenge.TypeTurnstile,
}
```

**Result:** Most users never see a challenge (invisible verification), suspicious traffic gets widget.

## Example 6: Mixed Strategy - Escalating Challenges

Start light, escalate to hard challenges for suspicious IPs.

```go
// First, configure with JavaScript by default
challengeConfig := challenge.Config{
    Enabled:     true,
    DefaultType: challenge.TypeJavaScript,
}

// Later, in your IP rules (config/ip_rules.json):
{
  "throttled_ips": [
    {
      "ip": "198.51.100.0/24",
      "type": "throttle",
      "challenge_type": "proof_of_work",
      "challenge_difficulty": 6
    }
  ]
}
```

**Result:** Normal users get JS challenge, suspicious subnet gets hard POW.

## Example 7: Whitelist Internal Tools

Skip challenges for monitoring/health checks.

```go
challengeConfig := challenge.Config{
    Enabled:        true,
    DefaultType:    challenge.TypeJavaScript,
    WhitelistPaths: []string{
        "/health",
        "/metrics",
        "/api/internal/",
    },
}
```

**Result:** Health checks pass through, all other paths get challenged.

## Example 8: DDoS Emergency Mode

Activate hard POW during active attack.

```go
var challengeConfig challenge.Config

func init() {
    challengeConfig = challenge.Config{
        Enabled:     false,  // Disabled by default
        DefaultType: challenge.TypeProofOfWork,
        Difficulty:  6,  // Very hard
    }
}

func enableEmergencyMode() {
    challengeConfig.Enabled = true
    log.Println("Emergency mode: Hard POW challenges active")
}
```

**Result:** Flip switch during attack to make every request expensive.

## Example 9: Per-IP Challenge Configuration

Different challenges for different threat levels.

**config/ip_rules.json:**
```json
{
  "throttled_ips": [
    {
      "ip": "203.0.113.0/24",
      "challenge_type": "javascript",
      "require_javascript": true
    },
    {
      "ip": "198.51.100.42",
      "challenge_type": "proof_of_work",
      "challenge_difficulty": 5
    },
    {
      "ip": "192.0.2.0/24",
      "challenge_type": "hcaptcha",
      "enable_challenge_mode": true
    }
  ]
}
```

**Result:** Different subnets get different challenge types based on threat assessment.

## Example 10: Testing Challenges Locally

Test all challenge types without real traffic.

```bash
# Start server
./bin/rhinowaf

# Test JavaScript challenge
curl -v http://localhost:8080/admin/
# Returns HTML page with JS auto-submit

# Test with real browser
open http://localhost:8080/admin/
# Challenge completes automatically after 2 seconds

# Verify session cookie
curl -v --cookie "waf_challenge_token=abc123..." http://localhost:8080/admin/
# Should pass through if token is valid
```

## Integration with IP Manager

Combine challenges with existing IP rules for defense-in-depth.

```go
// 1. Enable challenge system
challengeConfig := challenge.Config{
    Enabled:     true,
    DefaultType: challenge.TypeJavaScript,
}

// 2. Configure IP rules to trigger challenges
ipRule := &ddos.IPRule{
    IP:                   "198.51.100.0/24",
    Type:                 "throttle",
    RequireJavaScript:    true,
    ChallengeType:        "proof_of_work",
    ChallengeDifficulty:  4,
    EnableChallengeMode:  true,
}

// 3. Rules evaluated before challenge middleware
// If IP passes validation → check challenge session → allow/challenge
```

## Performance Tuning

### Difficulty Benchmarks

Measured on Intel i5-1135G7 (4 cores, 2.4GHz):

| Difficulty | Avg Time | Use Case |
|------------|----------|----------|
| 1 | 10-50ms | Testing only |
| 2 | 100-500ms | Light rate limiting |
| 3 | 500ms-2s | Standard protection |
| 4 | 1-5s | Strong protection |
| 5 | 5-30s | DDoS mitigation |
| 6 | 30-120s | Emergency mode |

**Recommendation:** Start with difficulty 3-4, increase if under attack.

### Session Memory Usage

- 1,000 sessions: ~200 KB
- 10,000 sessions: ~2 MB
- 100,000 sessions: ~20 MB

Sessions auto-expire after 15 minutes (new) or 1 hour (verified).

## Troubleshooting

### Challenge not showing

```go
// Check configuration
log.Printf("Challenge enabled: %v", challengeConfig.Enabled)
log.Printf("Path required: %v", challengeConfig.RequireForPaths)
log.Printf("Path whitelisted: %v", challengeConfig.WhitelistPaths)
```

### Sessions not persisting

- Check cookies enabled in browser
- Verify cookie domain matches
- Check SameSite/Secure flags for HTTPS

### hCaptcha/Turnstile errors

```bash
# Verify environment variables
echo $HCAPTCHA_SITE_KEY
echo $TURNSTILE_SECRET

# Check browser console for:
# - Invalid site key
# - CORS errors
# - Domain mismatch
```

### POW taking too long

```go
// Lower difficulty
challengeConfig.Difficulty = 3  // Instead of 6
```

## Security Best Practices

1. **Always use HTTPS** for CAPTCHA providers
2. **Whitelist carefully** - don't expose `/challenge/verify`
3. **Monitor failed verifications** for attack patterns
4. **Rate limit** the verify endpoint
5. **Log challenge completions** for analytics
6. **Rotate secrets** periodically for CAPTCHA providers
7. **Use Turnstile over hCaptcha** for better UX (if available)
8. **Start with JS challenges**, escalate to POW/CAPTCHA
9. **Test from multiple devices** - mobile, desktop, incognito
10. **Don't challenge health checks** - breaks monitoring
