# OAuth2 Integration

Added comprehensive OAuth2 authentication support for protecting specific paths with industry-standard OAuth2 providers.

## Configuration

OAuth2 is configured via `features.json`:

```json
{
  "oauth2": {
    "enabled": false,
    "client_id": "",
    "client_secret": "",
    "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_url": "https://oauth2.googleapis.com/token",
    "redirect_url": "https://yourdomain.com/oauth2/callback",
    "scopes": ["openid", "email", "profile"],
    "protected_paths": ["/admin", "/api/protected"],
    "session_timeout": 3600
  }
}
```

Or via environment variables:
- `OAUTH2_CLIENT_ID` - OAuth2 client ID from provider
- `OAUTH2_CLIENT_SECRET` - OAuth2 client secret
- `OAUTH2_AUTH_URL` - Provider authorization endpoint
- `OAUTH2_TOKEN_URL` - Provider token endpoint
- `OAUTH2_REDIRECT_URL` - Callback URL (must match provider config)

## Supported Providers

Works with any OAuth2-compliant provider:

**Google**:
- Auth URL: `https://accounts.google.com/o/oauth2/v2/auth`
- Token URL: `https://oauth2.googleapis.com/token`

**GitHub**:
- Auth URL: `https://github.com/login/oauth/authorize`
- Token URL: `https://github.com/login/oauth/access_token`

**Microsoft**:
- Auth URL: `https://login.microsoftonline.com/common/oauth2/v2.0/authorize`
- Token URL: `https://login.microsoftonline.com/common/oauth2/v2.0/token`

## Features

- Standard OAuth2 authorization code flow
- CSRF protection via state parameter
- Secure session management with HTTP-only cookies
- Configurable session timeout
- Per-path protection rules
- Automatic token exchange
- Session cleanup and expiry
- Logout endpoint

## Endpoints

- `/oauth2/callback` - OAuth2 callback handler (auto-created)
- `/oauth2/logout` - Logout endpoint (clears session)

## Protected Paths

Configure paths requiring authentication via `protected_paths`:

```json
"protected_paths": ["/admin", "/api/protected", "/dashboard"]
```

Any request to these paths will redirect to OAuth2 provider if not authenticated.

## Session Management

Sessions are stored in-memory with automatic cleanup:
- Default timeout: 3600 seconds (1 hour)
- Secure, HTTP-only cookies
- SameSite=Lax for CSRF protection
- Automatic expiry and garbage collection

## Security

- State parameter prevents CSRF attacks
- Secure cookie attributes (HttpOnly, Secure, SameSite)
- Session expiry enforcement
- Token storage in server memory (not client)
- Automatic cleanup of expired sessions/states

## Integration

OAuth2 middleware runs before fingerprinting and challenge systems:

```
Request → OAuth2 → Fingerprint → Challenge → WAF → Backend
```

Unauthenticated requests to protected paths redirect to OAuth2 provider.

## Example Setup (Google)

1. Create OAuth2 credentials at [Google Cloud Console](https://console.cloud.google.com)
2. Set redirect URI to `https://yourdomain.com/oauth2/callback`
3. Configure environment:
   ```bash
   export OAUTH2_CLIENT_ID="your-client-id"
   export OAUTH2_CLIENT_SECRET="your-client-secret"
   export OAUTH2_AUTH_URL="https://accounts.google.com/o/oauth2/v2/auth"
   export OAUTH2_TOKEN_URL="https://oauth2.googleapis.com/token"
   export OAUTH2_REDIRECT_URL="https://yourdomain.com/oauth2/callback"
   ```
4. Enable in features.json: `"enabled": true`
5. Restart RhinoWAF

## Monitoring

Sessions and states are tracked in-memory. Check logs for:
- Authentication failures
- Token exchange errors
- Session expiry events

Future versions may add Prometheus metrics for OAuth2 activity.
