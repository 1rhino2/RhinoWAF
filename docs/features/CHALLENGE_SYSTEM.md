# Challenge System Documentation

The RhinoWAF challenge system protects against automated attacks by requiring visitors to complete verification challenges before accessing protected resources.

**Status**:  **ENABLED by default in production** | **Version**: 2.0 | **Last Updated**: October 20, 2025

## Features

### Implemented Challenge Types

1. **JavaScript Challenge** (TypeJavaScript)
   - Requires JavaScript execution
   - 2-second delay before verification
   - Blocks headless browsers and bots without JS
   - Use case: Basic bot filtering

2. **Proof-of-Work Challenge** (TypeProofOfWork)
   - Client-side computational puzzle
   - Configurable difficulty (1-6 recommended)
   - Uses SHA-256 hashing
   - Use case: DDoS mitigation, rate limiting expensive operations

3. **hCaptcha Integration** (TypeHCaptcha)
   - Privacy-focused CAPTCHA provider
   - GDPR compliant
   - Requires site key and secret
   - Use case: Human verification for sensitive actions

4. **Cloudflare Turnstile** (TypeTurnstile)
   - Invisible/managed challenge
   - Better UX than traditional CAPTCHAs
   - Requires site key and secret
   - Use case: Seamless bot protection

## Configuration

### Environment Variables

```bash
# hCaptcha (get keys from https://hcaptcha.com)
export HCAPTCHA_SITE_KEY="your-site-key"
export HCAPTCHA_SECRET="your-secret-key"

# Cloudflare Turnstile (get keys from Cloudflare dashboard)
export TURNSTILE_SITE_KEY="your-site-key"
export TURNSTILE_SECRET="your-secret-key"
```

### Code Configuration

**Production defaults** in `cmd/rhinowaf/main.go`:

```go
challengeConfig := challenge.Config{
    Enabled:         true,  // ✓ ENABLED by default
    DefaultType:     challenge.TypeJavaScript,
    Difficulty:      5,     // For proof-of-work (1-6 recommended)
    WhitelistPaths:  []string{"/challenge/"},
    RequireForPaths: []string{},  // Add paths requiring challenges
}
```

**To customize:** Edit the configuration in `main.go` and rebuild.

### Configuration Options

- `Enabled` (bool): Master switch for challenge system
- `DefaultType` (ChallengeType): Challenge type to use
  - `challenge.TypeJavaScript` - Basic JS check
  - `challenge.TypeProofOfWork` - Computational puzzle
  - `challenge.TypeHCaptcha` - hCaptcha provider
  - `challenge.TypeTurnstile` - Cloudflare Turnstile
- `Difficulty` (int): Proof-of-work difficulty (1-6)
  - 1-2: Very easy (~100ms)
  - 3-4: Medium (~1-5 seconds)
  - 5-6: Hard (~10-60 seconds)
- `WhitelistPaths` ([]string): Paths that bypass challenges
- `RequireForPaths` ([]string): Paths that always require challenges (empty = smart detection)

## How It Works

### Challenge Flow

1. **Request arrives** → Middleware intercepts
2. **Check cookie** → Valid session token? → Allow through
3. **No valid session** → Issue challenge
4. **Client solves** → JavaScript/POW/CAPTCHA completed
5. **Verify solution** → POST to `/challenge/verify`
6. **Set cookie** → Session token (1 hour TTL)
7. **Allow access** → Challenge passed

### Session Management

- Sessions stored in-memory with automatic cleanup
- Default TTL: 15 minutes for new sessions
- Extended TTL: 1 hour after verification
- Sessions tied to IP address
- Token format: 64-character hex string (32 random bytes)

### Challenge Pages

Each challenge type renders a custom HTML page:

- **JavaScript**: Auto-submits after 2 seconds with JavaScript
- **Proof-of-Work**: Finds SHA-256 hash with N leading zeros
- **hCaptcha**: Embeds hCaptcha widget with callback
- **Turnstile**: Embeds Cloudflare Turnstile widget

## Integration Examples

### Protect Specific Endpoints

```go
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeJavaScript,
    RequireForPaths: []string{"/admin/", "/api/sensitive/"},
}
```

### Use Proof-of-Work for API Rate Limiting

```go
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeProofOfWork,
    Difficulty:      5,  // ~10-30 seconds on average CPU
    RequireForPaths: []string{"/api/"},
}
```

### Combine with IP Rules

```json
{
  "throttled_ips": [
    {
      "ip": "198.51.100.0/24",
      "type": "throttle",
      "require_javascript": true,
      "challenge_type": "proof_of_work",
      "challenge_difficulty": 4
    }
  ]
}
```

## API Reference

### POST /challenge/verify

Verify a completed challenge.

**Request Body:**
```json
{
  "token": "session-token",
  "type": "javascript|proof_of_work|hcaptcha|turnstile",
  "solution": "nonce-for-pow",
  "response": "captcha-response-token"
}
```

**Response:**
- `200 OK` - Challenge verified
- `400 Bad Request` - Invalid request
- `403 Forbidden` - Verification failed

## Security Considerations

### Session Security

- Sessions tied to IP (prevents token sharing)
- Tokens are 256-bit random (cryptographically secure)
- HttpOnly cookies (XSS protection)
- SameSite=Lax (CSRF mitigation)
- Automatic expiration and cleanup

### Challenge Security

- **JavaScript**: Defeats simple curl/wget
- **Proof-of-Work**: CPU cost prevents mass automation
- **hCaptcha**: Human verification with privacy focus
- **Turnstile**: Cloudflare's bot detection + challenge

### Bypass Prevention

- Whitelisted paths must be carefully chosen
- Don't whitelist `/challenge/verify` endpoint
- Use HTTPS in production (secure cookies)
- Monitor for session token harvesting

## Performance

### Memory Usage

- Each session: ~200 bytes
- 10,000 sessions: ~2 MB
- Automatic cleanup every 1 minute

### Latency

- JavaScript challenge: 2-second client delay
- Proof-of-Work (difficulty 4): 1-5 seconds
- hCaptcha: User-dependent (~3-10 seconds)
- Turnstile: Invisible or ~2 seconds
- Cookie verification: <1ms

### Scalability

Current implementation is in-memory and single-server.

**For multi-server deployments:**
- Use Redis for shared session storage
- Implement session replication
- Use sticky sessions at load balancer

## Troubleshooting

### Challenge not triggering

- Check `Enabled: true` in config
- Verify path not in `WhitelistPaths`
- Check cookies are enabled in browser

### hCaptcha/Turnstile not working

- Verify environment variables are set
- Check site key matches domain
- Confirm HTTPS in production (required by providers)
- Check browser console for errors

### Sessions expiring too fast

- Increase `sessionTTL` in `NewManager()`
- Check server time is synchronized (NTP)

### False positives (blocking legitimate users)

- Lower proof-of-work difficulty
- Switch to JavaScript challenge
- Add user paths to `WhitelistPaths`

## Advanced Usage

### Custom Challenge Types

Extend the `ChallengeType` enum and add custom verification logic in `VerifyHandler`.

### Dynamic Difficulty

Adjust POW difficulty based on threat level:

```go
difficulty := 3
if highTrafficDetected {
    difficulty = 5
}
```

### Challenge Escalation

Start with JavaScript, escalate to POW or CAPTCHA for suspicious IPs.

## Limitations

- In-memory sessions (not distributed)
- No persistent challenge history
- IP-based session binding (issues with NAT)
- CAPTCHA providers require external API calls

## Future Enhancements

- [ ] Redis session store for distributed deployments
- [ ] Challenge history and reputation scoring
- [ ] Device fingerprinting for session binding
- [ ] Rate limiting on challenge endpoints
- [ ] Admin UI for session management
- [ ] Metrics and monitoring integration
