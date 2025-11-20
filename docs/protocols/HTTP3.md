# HTTP/3 Support

RhinoWAF supports HTTP/3 via the QUIC protocol, providing faster connections and improved performance for modern clients.

## Configuration

### features.json

```json
{
  "http3": {
    "enabled": true,
    "port": ":443",
    "cert_file": "/path/to/cert.pem",
    "key_file": "/path/to/key.pem",
    "max_streams": 100,
    "idle_timeout": 30,
    "alt_svc_header": true,
    "domains": ["example.com", "www.example.com"]
  }
}
```

### Environment Variables

```bash
export HTTP3_ENABLED=true
export HTTP3_CERT_FILE=/path/to/cert.pem
export HTTP3_KEY_FILE=/path/to/key.pem
```

## Configuration Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| enabled | bool | false | Enable HTTP/3 server |
| port | string | :443 | QUIC listening port |
| cert_file | string | - | TLS certificate path (required) |
| key_file | string | - | TLS key path (required) |
| max_streams | int | 100 | Max concurrent QUIC streams |
| idle_timeout | int | 30 | Connection idle timeout (seconds) |
| alt_svc_header | bool | true | Send Alt-Svc headers for HTTP/1.1 clients |
| domains | []string | [] | Restrict Alt-Svc to specific domains |

## Features

1. **QUIC Protocol**: UDP-based transport for reduced latency
2. **Multiplexing**: True parallel streams without head-of-line blocking
3. **0-RTT**: Connection resumption for repeat visitors
4. **Protocol Negotiation**: Automatic fallback to HTTP/2 or HTTP/1.1
5. **Alt-Svc Headers**: Advertise HTTP/3 support to HTTP/1.1 clients
6. **TLS 1.3**: Modern encryption with improved handshake

## TLS Requirements

HTTP/3 requires TLS 1.3 certificates:

```bash
# Generate self-signed cert for testing
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

For production, use Let's Encrypt:

```bash
certbot certonly --standalone -d yourdomain.com
```

## How It Works

1. HTTP/1.1 client connects to port 8080
2. RhinoWAF sends Alt-Svc header: `h3=":443"; ma=2592000`
3. Client upgrades to HTTP/3 on port 443
4. Subsequent requests use QUIC protocol
5. Same middleware chain applies (OAuth2 → Fingerprint → Challenge → WAF)

## Client Support

HTTP/3 is supported by:
- Chrome 87+
- Firefox 88+
- Safari 14+
- Edge 87+
- curl 7.66+ (with --http3 flag)

## Testing

Check if HTTP/3 is working:

```bash
# Using curl
curl --http3 https://yourdomain.com

# Check Alt-Svc header
curl -I http://yourdomain.com:8080
```

## Security

- TLS 1.3 only (older versions disabled)
- ALPN negotiation: h3, h3-29
- Keep-alive every 15 seconds
- Idle connections closed after timeout
- Same WAF rules apply to HTTP/3 traffic

## Performance

HTTP/3 provides:
- 30-50% faster page loads on mobile networks
- Better performance on lossy connections
- Reduced latency for repeat visitors (0-RTT)
- No head-of-line blocking between streams

## Limitations

- Requires valid TLS certificates
- UDP port 443 must be open
- Some corporate firewalls block QUIC
- Automatic fallback to HTTP/2 or HTTP/1.1

## Monitoring

Check HTTP/3 connections in logs:

```
[HTTP/3] Starting server on :443
[HTTP/3] Client connected: 192.168.1.100
```

Prometheus metrics include HTTP/3 protocol tags.

## Troubleshooting

**HTTP/3 not starting:**
- Verify cert_file and key_file paths
- Check port 443 is not in use
- Ensure TLS 1.3 certificate

**Clients not upgrading:**
- Check Alt-Svc header in HTTP/1.1 response
- Verify UDP port 443 is reachable
- Some clients need explicit HTTP/3 flag

**Connection timeouts:**
- Increase idle_timeout
- Check firewall allows UDP traffic
- Verify network supports QUIC

For more help, see the main README.md or open an issue.
