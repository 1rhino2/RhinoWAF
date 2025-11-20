# IPv6 Support

RhinoWAF v2.5+ includes full IPv6 support for all security features and DDoS protection mechanisms.

## Features

### IP Address Handling
- Automatic detection and normalization of IPv6 addresses
- Support for compressed and expanded IPv6 notation
- IPv4-mapped IPv6 address handling (::ffff:192.168.1.1)
- Proper CIDR subnet matching for IPv6 ranges

### Security Features
All security features work seamlessly with IPv6:
- Rate limiting (Layer 4 and Layer 7)
- DDoS protection and adaptive throttling
- IP-based banning and whitelisting
- GeoIP lookups and country-based blocking
- Connection tracking and Slowloris detection
- Request fingerprinting

### Private Address Detection
The WAF correctly identifies IPv6 private ranges:
- `::1/128` - Loopback
- `fc00::/7` - Unique Local Addresses (ULA)
- `fe80::/10` - Link-Local addresses
- `ff00::/8` - Multicast addresses

### IP Extraction
IPv6 addresses are properly extracted from:
- Direct connections (RemoteAddr)
- X-Forwarded-For headers
- X-Real-IP headers
- CF-Connecting-IP (Cloudflare)

## Configuration

### IP Rules
Ban or whitelist IPv6 addresses in `config/ip_rules.json`:

```json
{
  "banned_ips": [
    {
      "ip": "2001:db8::1",
      "type": "ban",
      "reason": "Malicious activity"
    }
  ],
  "whitelisted_ips": [
    {
      "ip": "2001:db8:abcd::1",
      "type": "whitelist",
      "reason": "Trusted service"
    }
  ]
}
```

### GeoIP Database
Add IPv6 CIDR ranges to `config/geoip.json`:

```json
[
  {
    "cidr": "2001:db8::/32",
    "country_code": "US",
    "country_name": "United States"
  }
]
```

The database automatically includes IPv6 private ranges:
- `::1/128` - Localhost (IPv6)
- `fc00::/7` - Private (IPv6 ULA)
- `fe80::/10` - Private (IPv6 Link-Local)
- `ff00::/8` - Multicast (IPv6)

### Trusted Proxies
Configure trusted IPv6 proxy ranges for proper client IP extraction:

```go
security.SetTrustedProxies([]string{
    "::1/128",
    "fc00::/7",
    "2001:db8::/32",
})
```

## API

### New Helper Functions

```go
// Check IP version
version := security.GetIPVersion("2001:db8::1") // Returns 6

// Normalize IPv6 address
normalized := security.NormalizeIP("2001:0db8:0000:0000:0000:0000:0000:0001")
// Returns "2001:db8::1"

// Expand IPv6 to full form
expanded := security.ExpandIPv6("2001:db8::1")
// Returns "2001:0db8:0000:0000:0000:0000:0000:0001"

// Check if address is IPv6
isV6 := security.IsIPv6("2001:db8::1") // Returns true

// Check if address is in private range
isPrivate := security.IsPrivateIP("fc00::1") // Returns true

// Check specific IPv6 types
security.IsIPv6LinkLocal("fe80::1") // Returns true
security.IsIPv6UniqueLocal("fc00::1") // Returns true
security.IsIPv6Loopback("::1") // Returns true
```

## Dual Stack Support

RhinoWAF handles dual-stack environments transparently:
- IPv4 and IPv6 connections are tracked separately
- Rate limits apply per IP (not shared between v4/v6)
- A client using both IPv4 and IPv6 is treated as two separate IPs
- GeoIP lookups work for both protocols

## Testing

Test IPv6 support using curl or similar tools:

```bash
# IPv6 request
curl -6 http://[2001:db8::1]:8080/

# IPv4-mapped IPv6
curl http://[::ffff:192.168.1.1]:8080/

# With proxy headers
curl -H "X-Forwarded-For: 2001:db8::1" http://localhost:8080/
```

## Performance

IPv6 operations have minimal performance impact:
- IP parsing: Same speed as IPv4 (Go's net package optimized)
- CIDR matching: Slightly slower than IPv4 (128-bit vs 32-bit)
- Memory: IPv6 tracking uses ~16 bytes per IP vs 4 bytes for IPv4
- GeoIP lookups: Performance depends on database size, not IP version

## Migration Notes

Existing IPv4 configurations continue to work without changes. IPv6 support is additive and doesn't break backward compatibility.

If you have custom IP validation logic, update it to handle both:
- Use `security.ValidateIP()` instead of custom regex
- Use `security.NormalizeIP()` for consistent IP storage
- Check IP version with `security.GetIPVersion()` if different handling needed

## Limitations

Current known limitations:
- IPv6 zone identifiers (e.g., `fe80::1%eth0`) are not preserved
- IPv6 scope IDs are stripped during normalization
- Some legacy proxy headers may not properly format IPv6 addresses

## Future Enhancements

Planned for future releases:
- IPv6-specific rate limiting profiles
- Subnet-based tracking (track /64 instead of individual IPs)
- IPv6 reputation databases
- ASN lookups for IPv6 ranges
