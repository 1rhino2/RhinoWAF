# CSRF Protection

RhinoWAF v2.4.2 includes comprehensive CSRF (Cross-Site Request Forgery) protection to prevent unauthorized actions on behalf of authenticated users.

## Overview

CSRF attacks trick users into performing unwanted actions on a web application where they're authenticated. RhinoWAF provides two protection patterns:

1. **Server-side token validation** (default) - Tokens stored in memory, validated on server
2. **Double-submit cookie pattern** (stateless) - Token sent both as cookie and header/form field

## Configuration

CSRF protection is configured in `config/features.json`:

```json
{
  "csrf": {
    "enabled": true,
    "token_length": 32,
    "token_ttl_seconds": 3600,
    "cookie_name": "csrf_token",
    "header_name": "X-CSRF-Token",
    "form_field_name": "csrf_token",
    "secure_cookie": false,
    "same_site": "Lax",
    "exempt_methods": ["GET", "HEAD", "OPTIONS", "TRACE"],
    "exempt_paths": ["/health", "/metrics", "/challenge/", "/fingerprint/", "/csrf/token"],
    "double_submit": false
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable CSRF protection |
| `token_length` | int | `32` | Length of generated tokens in bytes |
| `token_ttl_seconds` | int | `3600` | Token lifetime in seconds |
| `cookie_name` | string | `"csrf_token"` | Name of CSRF cookie |
| `header_name` | string | `"X-CSRF-Token"` | HTTP header for token |
| `form_field_name` | string | `"csrf_token"` | Form field name for token |
| `secure_cookie` | bool | `false` | Set cookie Secure flag (HTTPS only) |
| `same_site` | string | `"Lax"` | SameSite cookie attribute |
| `exempt_methods` | []string | `["GET", "HEAD", "OPTIONS", "TRACE"]` | HTTP methods exempt from CSRF checks |
| `exempt_paths` | []string | Various | Paths exempt from CSRF checks |
| `double_submit` | bool | `false` | Use stateless double-submit pattern |

## Usage

### Getting a CSRF Token

**Endpoint**: `GET /csrf/token`

Returns a JSON response with token information:

```json
{
  "csrf_token": "abc123def456...",
  "header": "X-CSRF-Token",
  "field": "csrf_token"
}
```

### Including Tokens in Requests

#### 1. HTML Forms

Add the token as a hidden input field:

```html
<form method="POST" action="/api/submit">
  <input type="hidden" name="csrf_token" value="abc123def456...">
  <input type="text" name="data">
  <button type="submit">Submit</button>
</form>
```

#### 2. JavaScript Fetch API

Include token in request header:

```javascript
// Get token first
const response = await fetch('/csrf/token');
const data = await response.json();

// Use token in subsequent requests
await fetch('/api/submit', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': data.csrf_token
  },
  body: JSON.stringify({ key: 'value' })
});
```

#### 3. jQuery/AJAX

```javascript
$.ajax({
  url: '/api/submit',
  type: 'POST',
  headers: {
    'X-CSRF-Token': tokenValue
  },
  data: { key: 'value' },
  success: function(response) {
    console.log('Success');
  }
});
```

## Protection Patterns

### Server-side Validation (Default)

- Tokens stored in server memory mapped to session IDs
- Each user session gets a unique token
- Tokens automatically expire after TTL
- More secure but requires server state

**Best for**: Applications with user sessions, high-security requirements

### Double-Submit Cookie Pattern

- Token sent both as cookie and in header/form
- Server validates both values match
- Completely stateless
- Suitable for distributed systems

**Best for**: Stateless APIs, microservices, load-balanced deployments

Enable with `"double_submit": true` in config.

## Security Considerations

### 1. Use HTTPS in Production

Always set `"secure_cookie": true` when using HTTPS:

```json
{
  "csrf": {
    "secure_cookie": true
  }
}
```

### 2. SameSite Cookie Attribute

Choose appropriate SameSite value:

- `Strict`: Highest security, may break legitimate cross-site flows
- `Lax`: (Default) Good balance between security and usability
- `None`: Least secure, requires `secure_cookie: true`

### 3. Token Rotation

Tokens automatically expire based on TTL. Clients should:
- Request new tokens when expired
- Handle 403 Forbidden responses by refreshing token

### 4. Exempt Paths Carefully

Only exempt paths that:
- Don't perform state-changing operations
- Are truly public endpoints
- Don't access sensitive data

## Integration with Other Features

CSRF protection works alongside other RhinoWAF features:

- **Challenge System**: CSRF token required after challenge completion
- **Fingerprinting**: Token tied to browser fingerprint for enhanced security
- **OAuth2**: CSRF tokens protect OAuth callback endpoints
- **Rate Limiting**: Failed CSRF validations count toward rate limits

## Troubleshooting

### "CSRF validation failed" Error

**Cause**: Token missing, expired, or invalid

**Solutions**:
1. Verify token is included in request (header or form field)
2. Check token hasn't expired (default 1 hour)
3. Ensure request method isn't exempt
4. Verify path isn't in exempt list

### Token Not Persisting Across Requests

**Cause**: Session ID not maintained

**Solutions**:
1. Check session cookie is set correctly
2. Verify cookie isn't blocked by browser
3. Consider using double-submit pattern for stateless apps

### Performance Impact

**Minimal overhead**:
- Token generation: ~1ms per request
- Validation: <1ms per request
- Memory: ~100 bytes per active session
- Auto-cleanup runs every 5 minutes

## Testing CSRF Protection

### Test Valid Request

```bash
# Get token
TOKEN=$(curl -s http://localhost:8080/csrf/token | jq -r .csrf_token)

# Use token
curl -X POST http://localhost:8080/api/submit \
  -H "X-CSRF-Token: $TOKEN" \
  -d '{"data": "value"}'
```

### Test Invalid Request (Should Fail)

```bash
curl -X POST http://localhost:8080/api/submit \
  -d '{"data": "value"}'
# Expected: 403 Forbidden - CSRF validation failed
```

### Test Exempt Path

```bash
curl -X POST http://localhost:8080/health
# Expected: 200 OK (CSRF not required)
```

## Migration Guide

### Enabling CSRF Protection

1. **Update configuration** in `features.json`
2. **Update client code** to include tokens
3. **Test thoroughly** before production deployment
4. **Monitor logs** for failed validations

### Disabling Temporarily

Set `"enabled": false` in config (not recommended for production).

## Best Practices

1. **Always use CSRF protection** for state-changing operations
2. **Keep token TTL reasonable** (1-24 hours)
3. **Use HTTPS** with secure cookies in production
4. **Implement client-side token refresh** logic
5. **Log CSRF failures** for security monitoring
6. **Don't expose tokens** in URLs or logs
7. **Rotate tokens** on authentication events
8. **Use SameSite=Lax** minimum for cookies

## Examples

### React Application

```javascript
// Token provider component
const CSRFContext = React.createContext(null);

function CSRFProvider({ children }) {
  const [token, setToken] = useState(null);

  useEffect(() => {
    fetch('/csrf/token')
      .then(res => res.json())
      .then(data => setToken(data.csrf_token));
  }, []);

  return (
    <CSRFContext.Provider value={token}>
      {children}
    </CSRFContext.Provider>
  );
}

// Usage in component
function FormComponent() {
  const csrfToken = useContext(CSRFContext);

  const handleSubmit = async (e) => {
    e.preventDefault();
    await fetch('/api/submit', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': csrfToken,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formData)
    });
  };

  return <form onSubmit={handleSubmit}>...</form>;
}
```

### Go Backend Integration

```go
// Generate token for user session
token, err := csrfManager.GenerateToken(w, r)
if err != nil {
    log.Printf("Failed to generate CSRF token: %v", err)
    return
}

// Include in template data
data := map[string]interface{}{
    "CSRFToken": token,
    "User": user,
}
tmpl.Execute(w, data)
```

## Related Documentation

- [Challenge System](CHALLENGE_SYSTEM.md)
- [Fingerprinting](FINGERPRINTING.md)
- [OAuth2 Integration](../config/features.json)
