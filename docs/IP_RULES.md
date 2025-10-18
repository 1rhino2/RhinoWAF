# IP Rules Configuration Guide

Complete reference for RhinoWAF's advanced IP control system.

## Overview

RhinoWAF supports per-IP controls with 60+ configuration options across multiple categories:

- **Time-based restrictions** - Business hours, specific days
- **Path & method controls** - Allowlists/blocklists for paths and HTTP methods
- **Request pattern matching** - Query params, headers, referers, cookies
- **Content controls** - File types, sizes, content-types
- **Behavioral limits** - Burst protection, session management
- **Protocol requirements** - HTTPS, TLS versions, HTTP/2
- **Bot detection** - Headless browsers, scrapers, user agents
- **Custom rules** - Regex-based validation logic

## IP Rule Types

### 1. Banned IPs
Complete blocking with optional expiration.

```json
{
  "ip": "192.168.1.100",
  "type": "ban",
  "reason": "Repeated attacks",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

### 2. Whitelisted IPs
Trusted IPs with optional rule bypass.

```json
{
  "ip": "10.0.0.1",
  "type": "whitelist",
  "whitelist_override": true,
  "notes": "Admin - bypass all checks"
}
```

### 3. Throttled IPs
Rate limiting with advanced controls.

```json
{
  "ip": "198.51.100.100",
  "type": "throttle",
  "throttle_percent": 50,
  "min_request_interval": 1000,
  "max_burst_size": 10,
  "burst_window_ms": 5000
}
```

### 4. Challenged IPs
Require verification (CAPTCHA, JS challenge, etc).

```json
{
  "ip": "192.0.2.150",
  "type": "challenge",
  "require_javascript": true,
  "max_concurrent_conns": 5
}
```

### 5. Monitored IPs
Watch closely without blocking.

```json
{
  "ip": "198.51.100.25",
  "type": "monitor",
  "tags": ["suspicious", "high-volume"]
}
```

## Advanced Controls

### Time-Based Restrictions

**Business Hours Only:**
```json
{
  "ip": "203.0.113.200",
  "allowed_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
  "allowed_days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
  "timezone": "America/New_York"
}
```

**Block Specific Times:**
```json
{
  "blocked_hours": [0, 1, 2, 3, 4, 5],
  "blocked_days": ["Sat", "Sun"]
}
```

### Path & Method Controls

**API Access Restrictions:**
```json
{
  "ip": "192.0.2.75",
  "allowed_paths": ["/api/v1/*"],
  "blocked_paths": ["/api/v2/*", "/admin/*"],
  "allowed_methods": ["GET", "POST"],
  "blocked_methods": ["DELETE", "PUT"]
}
```

**Per-Path Rate Limits:**
```json
{
  "rate_limit_by_path": {
    "/api/v1/search": 100,
    "/api/v1/upload": 10,
    "/api/v1/export": 5
  }
}
```

### Request Pattern Controls

**Required Headers:**
```json
{
  "required_headers": ["X-API-Key", "X-Client-ID"],
  "blocked_headers": ["X-Forwarded-For"]
}
```

**Referer Validation:**
```json
{
  "allowed_referers": ["*example.com*", "*trusted.org*"],
  "blocked_referers": ["*spam.site*"]
}
```

**Cookie Requirements:**
```json
{
  "require_cookies": ["session_id", "device_id"],
  "require_valid_session": true,
  "max_session_duration": 86400
}
```

### Content Controls

**File Upload Restrictions:**
```json
{
  "allowed_file_exts": [".jpg", ".png", ".pdf"],
  "blocked_file_exts": [".php", ".exe", ".sh"],
  "max_upload_size": 10485760,
  "allowed_content_types": ["image/*", "application/pdf"]
}
```

**Size Limits:**
```json
{
  "max_upload_size": 5242880,
  "max_url_length": 2048,
  "max_header_size": 16384
}
```

### User Agent Controls

**Mobile App Client:**
```json
{
  "allowed_user_agents": ["*MyApp/*", "*iOS*", "*Android*"],
  "blocked_user_agents": ["*bot*", "*crawler*"],
  "block_headless": true,
  "block_bots": true
}
```

### Behavioral Controls

**Burst Protection:**
```json
{
  "min_request_interval": 1000,
  "max_burst_size": 10,
  "burst_window_ms": 5000,
  "max_concurrent_conns": 20
}
```

### Protocol Controls

**HTTPS & TLS Requirements:**
```json
{
  "require_https": true,
  "require_http2": true,
  "min_tls_version": "1.2",
  "allowed_ciphers": ["TLS_AES_128_GCM_SHA256"],
  "blocked_protocols": ["HTTP/1.0"]
}
```

**Port Restrictions:**
```json
{
  "allowed_ports": [443, 8443],
  "blocked_ports": [80, 8080]
}
```

### Custom Rules

**Advanced Pattern Matching:**
```json
{
  "custom_rules": [
    {
      "name": "Block SQL Injection",
      "type": "query",
      "pattern": ".*(union|select|insert|drop).*",
      "action": "block",
      "case_sensitive": false
    },
    {
      "name": "Require Auth Header",
      "type": "header",
      "pattern": "Bearer [A-Za-z0-9]{32}",
      "action": "allow"
    }
  ]
}
```

## Geo Rules

Country-based access control.

```json
{
  "geo_rules": [
    {
      "country_code": "CN",
      "action": "block",
      "priority": 10,
      "allowed_paths": ["/api/public/*"]
    },
    {
      "country_code": "RU",
      "action": "challenge",
      "throttle_percent": 60
    }
  ]
}
```

**Actions:** `allow`, `block`, `challenge`, `throttle`

## ASN Rules

Block/allow by Autonomous System Number.

```json
{
  "asn_rules": [
    {
      "asn": "AS13335",
      "organization": "Cloudflare",
      "action": "allow"
    },
    {
      "asn": "AS12345",
      "action": "block",
      "throttle_percent": 90
    }
  ]
}
```

## Global Rules

WAF-wide policies and security features.

```json
{
  "global_rules": {
    "default_action": "allow",
    "max_requests_per_ip": 1000,
    "max_connections_per_ip": 50,
    "global_rate_limit_window": 60,
    
    "block_proxies": false,
    "block_tor": true,
    "block_hosting": false,
    "block_empty_user_agent": true,
    "block_suspicious_ua": true,
    "block_known_bad_bots": true,
    "allow_search_engine_bots": true,
    "require_valid_user_agent": true,
    
    "blocked_countries": ["KP", "IR", "SY"],
    "challenge_countries": ["BR", "IN", "PK"],
    "require_auth_countries": ["CN", "RU"],
    
    "max_url_length": 4096,
    "max_header_count": 50,
    "max_cookie_count": 30,
    "max_request_body_size": 10485760,
    
    "block_sql_injection": true,
    "block_xss": true,
    "block_path_traversal": true,
    "block_command_injection": true,
    "block_xml_injection": true,
    "block_ssrf": true,
    "block_ldap_injection": true,
    "block_template_injection": true,
    
    "require_https": false,
    "require_modern_tls": true,
    "block_old_http_versions": true,
    
    "allowed_methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
    "blocked_paths": ["/phpmyadmin/*", "/.git/*", "/.env"],
    
    "rate_limit_by_endpoint": true,
    "enable_geo_fencing": true,
    "enable_asn_blocking": true,
    
    "log_all_requests": false,
    "log_blocked_only": true,
    
    "enable_challenge_mode": true,
    "challenge_type": "js",
    "challenge_difficulty": 5,
    "session_timeout": 3600,
    
    "enable_fingerprinting": true,
    "block_repeated_fingerprint": false,
    "max_fingerprint_reuse": 3
  }
}
```

## Complete Field Reference

### IPRule Fields

| Field | Type | Description |
|-------|------|-------------|
| `ip` | string | IP address |
| `type` | string | ban/whitelist/monitor/challenge/throttle |
| `reason` | string | Why this rule exists |
| `created_at` | datetime | When created |
| `expires_at` | datetime | When rule expires (optional) |
| `priority` | int | Higher = checked first |
| `notes` | string | Additional info |
| `tags` | []string | Labels for organization |

**Advanced Controls:**
| Field | Type | Description |
|-------|------|-------------|
| `rate_limit_override` | int | Custom rate limit |
| `allowed_paths` | []string | Allowed URL patterns |
| `blocked_paths` | []string | Blocked URL patterns |
| `allowed_methods` | []string | Allowed HTTP methods |
| `blocked_methods` | []string | Blocked HTTP methods |
| `require_auth` | bool | Require authentication |
| `max_concurrent_conns` | int | Max simultaneous connections |
| `throttle_percent` | int | Reduce rate by % (1-100) |
| `whitelist_override` | bool | Bypass all other rules |

**Time Controls:**
| Field | Type | Description |
|-------|------|-------------|
| `allowed_hours` | []int | Hours (0-23) allowed |
| `blocked_hours` | []int | Hours blocked |
| `allowed_days` | []string | Days allowed (Mon, Tue, ...) |
| `blocked_days` | []string | Days blocked |
| `timezone` | string | Timezone for checks |

**Request Pattern:**
| Field | Type | Description |
|-------|------|-------------|
| `allowed_query_params` | []string | Allowed query patterns (regex) |
| `blocked_query_params` | []string | Blocked query patterns |
| `required_headers` | []string | Required HTTP headers |
| `blocked_headers` | []string | Blocked headers |
| `allowed_referers` | []string | Allowed referer patterns |
| `blocked_referers` | []string | Blocked referers |
| `require_cookies` | []string | Required cookies |

**Content:**
| Field | Type | Description |
|-------|------|-------------|
| `allowed_content_types` | []string | Allowed Content-Type |
| `blocked_content_types` | []string | Blocked Content-Type |
| `max_upload_size` | int64 | Max body size (bytes) |
| `max_url_length` | int | Max URL length |
| `max_header_size` | int | Max total header size |
| `blocked_file_exts` | []string | Blocked extensions |
| `allowed_file_exts` | []string | Allowed extensions |

**Behavioral:**
| Field | Type | Description |
|-------|------|-------------|
| `min_request_interval` | int | Min ms between requests |
| `max_burst_size` | int | Max requests in burst |
| `burst_window_ms` | int | Burst window (ms) |
| `max_session_duration` | int | Max session length (sec) |
| `require_valid_session` | bool | Require valid session |
| `block_headless` | bool | Block headless browsers |
| `block_bots` | bool | Block known bots |
| `require_javascript` | bool | Require JS challenge |

**User Agent:**
| Field | Type | Description |
|-------|------|-------------|
| `allowed_user_agents` | []string | Allowed UA patterns |
| `blocked_user_agents` | []string | Blocked UA patterns |

**Protocol:**
| Field | Type | Description |
|-------|------|-------------|
| `allowed_ports` | []int | Allowed ports |
| `blocked_ports` | []int | Blocked ports |
| `require_https` | bool | Force HTTPS |
| `require_http2` | bool | Require HTTP/2 |
| `blocked_protocols` | []string | Blocked protocols |
| `allowed_ciphers` | []string | Allowed TLS ciphers |
| `min_tls_version` | string | Min TLS version |

**Custom:**
| Field | Type | Description |
|-------|------|-------------|
| `custom_headers` | map[string]string | Headers to add |
| `custom_rules` | []CustomRule | Custom validation |
| `rate_limit_by_path` | map[string]int | Per-path limits |

## Examples

See `config/ip_rules.example.json` for complete real-world examples.

## Wildcard Patterns

Use `*` for wildcard matching:
- `*example.com*` - Contains "example.com"
- `*.example.com` - Ends with ".example.com"
- `/api/*` - Starts with "/api/"

## Priority System

Rules are checked in order:
1. Whitelist (if `whitelist_override: true`, skip all other checks)
2. Ban
3. Throttle
4. Challenge
5. Monitor
6. Geo rules
7. ASN rules
8. Global rules
