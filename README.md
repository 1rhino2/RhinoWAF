# RhinoWAF

A self-hosted Layer 7 web application firewall written in Go. You run it on your
own VPS, in front of nginx, Caddy, or Traefik, and it soaks up floods, bots, and
the usual injection noise before any of it reaches your app.

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/1rhino2/RhinoWAF?style=social)](https://github.com/1rhino2/RhinoWAF)

Docs and benchmarks: https://1rhino2.github.io/RhinoWAF/

## What it does

RhinoWAF sits between the internet and your backend and handles the Layer 7 side
of things:

- Rate limiting and DDoS mitigation (burst detection, slowloris, reputation)
- Per-IP rules with geo and ASN blocking
- Challenge pages (JavaScript, proof-of-work, hCaptcha, Cloudflare Turnstile)
- Browser fingerprinting to catch bot networks sharing one browser
- CSRF token validation
- HTTP request smuggling detection
- Input sanitization (SQLi, XSS, path traversal, command injection)
- WebSocket connection and message limits
- Reverse proxy with multi-vhost routing

Good fit for a website, panel, store, or API on HTTP/HTTPS (ports 80/443).

It is not a Minecraft proxy. If you need to protect a Java game port, use
TCPShield or similar for the game server and put RhinoWAF in front of the website
and API.

## Status

Version 1.0.x, active development. It is solid enough to self-host, but treat it
like software you test in staging first, not a drop-in swap for Cloudflare or
ModSecurity. Run it against your real Host headers, APIs, and webhooks before you
point production traffic at it. No warranty, you own the downtime risk.

## Quick start

```bash
git clone https://github.com/1rhino2/RhinoWAF.git
cd RhinoWAF
go build -o rhinowaf ./cmd/rhinowaf
./rhinowaf
```

That starts the WAF on `:8080`, proxying to a backend at `http://localhost:9000`.
Point it somewhere else without rebuilding:

```bash
./rhinowaf -listen :8443 -backend http://127.0.0.1:3000
```

Check the version:

```bash
./rhinowaf -version
# RhinoWAF 1.0.5 (built ...)
```

You can also grab a prebuilt binary from the
[releases page](https://github.com/1rhino2/RhinoWAF/releases) instead of building.

## Configuration

Everything lives under `config/`. You no longer edit `main.go` and rebuild for
the common knobs, the files and flags below cover it.

| File | Controls |
|------|----------|
| `config/features.json` | App middleware: listen address, backend, challenge, fingerprinting, websocket, server timeouts, logging |
| `config/ip_rules.json` | Per-IP rules, geo rules, global rate limits, proxy/Tor/hosting blocking |
| `config/geoip.json` | CIDR to country mapping for geo rules |
| `config/backends.json` | Multi-vhost routing (one instance, many domains to many backends) |

`features.json` is read at startup. A missing file just uses the built-in
defaults, so you can delete it and the WAF still runs. A malformed file, a bad
value, or an unknown field stops startup with a clear error instead of silently
dropping protection. Example:

```json
{
  "server": { "listen": ":8080", "read_timeout_seconds": 30 },
  "backend": { "proxy_url": "http://localhost:9000" },
  "challenge_system": { "enabled": true, "default_type": "javascript", "pow_difficulty": 5 },
  "fingerprinting": { "enabled": true, "max_ips_per_fingerprint": 5 },
  "websocket": { "enabled": true, "max_connections_per_ip": 10 }
}
```

See `config/features.example.json` for the full annotated set of fields.

`ip_rules.json` and `geoip.json` hot-reload while the WAF is running, so IP bans,
geo rules, and rate limits take effect without a restart (see Hot-reload below).

### Flags and environment

Flags win over environment variables, which win over `features.json`.

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `-listen` | `RHINOWAF_LISTEN` | `:8080` | Listen address |
| `-backend` | `RHINOWAF_BACKEND` | `http://localhost:9000` | Fallback backend when there is no `backends.json` |
| `-config-dir` | `RHINOWAF_CONFIG_DIR` | `./config` | Where the config files live |
| `-log-dir` | `RHINOWAF_LOG_DIR` | `./logs` | Where log files are written |
| `-features` | `RHINOWAF_FEATURES` | `<config-dir>/features.json` | Path to features.json |
| `-version` | | | Print version and exit |

Secrets stay in environment variables (never in the config files):

```bash
export HCAPTCHA_SITE_KEY=...   HCAPTCHA_SECRET=...
export TURNSTILE_SITE_KEY=...  TURNSTILE_SECRET=...
export OAUTH2_CLIENT_ID=...    OAUTH2_CLIENT_SECRET=...
export ABUSEIPDB_API_KEY=...   IPQS_API_KEY=...
export JWT_SECRET=...
```

### Per-IP rules

`ip_rules.json` supports a large set of per-IP controls. Short version:

```json
{
  "version": "2.0",
  "banned_ips": [
    { "ip": "192.0.2.10", "type": "ban", "reason": "repeated attacks" }
  ],
  "whitelisted_ips": [
    { "ip": "10.0.0.1", "type": "whitelist", "whitelist_override": true }
  ],
  "geo_rules": [
    { "country_code": "CN", "action": "challenge", "throttle_percent": 40 },
    { "country_code": "KP", "action": "block" }
  ],
  "global_rules": {
    "default_action": "allow",
    "block_proxies": true,
    "block_tor": true,
    "block_hosting": true,
    "max_requests_per_ip": 100,
    "max_connections_per_ip": 10,
    "block_empty_user_agent": true,
    "block_suspicious_ua": true
  }
}
```

Each rule also supports time windows, path and method filters, header and cookie
checks, content-type and upload limits, protocol enforcement, and user-agent
rules. Full field reference: [docs/configuration/IP_RULES.md](docs/configuration/IP_RULES.md).

## Challenges

Four challenge types, set `default_type` in `features.json`:

- `javascript` - short JS execution requirement, blocks plain curl/wget
- `proof_of_work` - client-side SHA-256 puzzle, difficulty 1 to 8
- `hcaptcha` - needs `HCAPTCHA_SITE_KEY` / `HCAPTCHA_SECRET`
- `turnstile` - Cloudflare Turnstile, needs `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET`

A visitor completes the challenge once, gets a cookie, and passes through on
later requests. Proof-of-work is the one that makes a sustained flood expensive
with no external dependency. See [docs/features/CHALLENGE_SYSTEM.md](docs/features/CHALLENGE_SYSTEM.md).

## Fingerprinting

Fingerprinting is on by default. On first visit a small script collects a canvas
signature, WebGL renderer, fonts, and hardware hints, hashes them, and sets a
cookie. If the same fingerprint shows up across too many IPs, that is a bot
network signal. Tune `max_ips_per_fingerprint` and friends in `features.json`,
or turn on `require_client_data` to block headless browsers that cannot produce
canvas/WebGL data. See [docs/features/FINGERPRINTING.md](docs/features/FINGERPRINTING.md).

## Request smuggling

Runs before the other checks and scores each request for CL.TE / TE.CL / TE.TE
conflicts, duplicate length/encoding headers, header obfuscation, and protocol
violations. Each violation has a severity 1 to 5 and the WAF blocks at or above a
threshold (4 by default). Metrics land in Prometheus. See
[docs/features/SMUGGLING_DETECTION.md](docs/features/SMUGGLING_DETECTION.md).

## Observability

Health, metrics, and reload endpoints are restricted to localhost.

```bash
curl http://localhost:8080/health        # status, uptime, memory, version
curl http://localhost:8080/metrics       # Prometheus
curl -X POST http://localhost:8080/reload # force a config reload
```

Metrics cover requests (allowed/blocked by reason), challenge issue/pass/fail
counts, fingerprint stats, request latency histograms, and config reloads. Grafana
query examples are in [docs/CHANGELOGS/V2.3_FEATURES.md](docs/CHANGELOGS/V2.3_FEATURES.md).

Attack logs are JSON, one event per line, at `logs/ddos.log`:

```bash
tail -f logs/ddos.log | jq '.message'
jq -r '.severity' logs/ddos.log | sort | uniq -c
```

## Hot-reload

`ip_rules.json` and `geoip.json` are watched for changes and reloaded after a
short debounce, no restart needed. You can also reload on demand:

```bash
curl -X POST http://localhost:8080/reload   # HTTP (localhost)
kill -SIGHUP <pid>                          # signal
```

If a reload hits invalid JSON, the previous config stays active.

## Deployment

Build a stripped binary and run it behind your existing proxy:

```bash
go build -trimpath -ldflags="-s -w" -o rhinowaf ./cmd/rhinowaf
```

RhinoWAF shuts down cleanly on SIGINT/SIGTERM and drains in-flight requests
(15 second grace), so it behaves under a process manager. Minimal systemd unit:

```ini
[Unit]
Description=RhinoWAF
After=network.target

[Service]
WorkingDirectory=/opt/rhinowaf
ExecStart=/opt/rhinowaf/rhinowaf -config-dir /opt/rhinowaf/config -log-dir /var/log/rhinowaf
Restart=on-failure
Environment=TURNSTILE_SITE_KEY=...
Environment=TURNSTILE_SECRET=...

[Install]
WantedBy=multi-user.target
```

The WAF's own listener has read/write/idle timeouts set, so it is not itself an
easy slowloris target. Adjust them under `server` in `features.json`.

## Benchmarks

Numbers from the `benchmarks/` suite against an OWASP-style scenario set (1,518
requests across 15 traffic patterns). Run it yourself with `go test ./benchmarks/...`.

| Attack type | Detection |
|-------------|-----------|
| SQL injection | 100% |
| XSS | 100% |
| Credential stuffing | 100% |
| File upload attacks | 100% |
| Web scrapers | 100% |
| Bot attacks | ~55% (modern API user-agents are allowed on purpose) |

Legitimate traffic (browser, e-commerce, SaaS, mobile, crawlers, webhooks,
GraphQL) passed at or near 100%, with a low single-digit false-positive rate
under peak-hour load. Overall true-positive rate is around 87% because bot
detection intentionally lets modern API clients (curl 8.x, python-requests)
through to avoid blocking real automation. Latency was sub-millisecond mean on
allowed requests. Tune `ip_rules.json` for your own traffic mix.

## Paid setup (optional)

Self-hosting is free under AGPL. If you would rather not fight config files, I
also do the hands-on deploy.

| Package | What you get | Price |
|---------|--------------|-------|
| Go-live | VPS install, Traefik or nginx in front of your app, Turnstile on flood traffic, L7 rules tuned to your domain, smoke test, short handoff doc | $125 to $250 one-time |
| Care | Weekly health check, small config fixes after you are live | $99/mo (optional) |
| Custom | Admin UI, multi-site, client handoff package | quoted |

Terms: fixed scope, half up front, half once traffic is passing through the WAF.
PayPal or Cash App after scope is agreed in writing.

Contact: Discord `1rhino2`, or open a
[GitHub Discussion](https://github.com/1rhino2/RhinoWAF/discussions) with your
stack (VPS, domain, Traefik yes/no). Other work (bots, APIs, scrapers, sites) is
at [1rhino2.github.io](https://1rhino2.github.io).

## Documentation

- [IP rules](docs/configuration/IP_RULES.md), [multi-vhost](docs/configuration/MULTI_VHOST.md), [production config](docs/configuration/PRODUCTION_CONFIG.md)
- [Challenges](docs/features/CHALLENGE_SYSTEM.md), [fingerprinting](docs/features/FINGERPRINTING.md), [CSRF](docs/features/CSRF_PROTECTION.md), [smuggling](docs/features/SMUGGLING_DETECTION.md), [IPv6](docs/features/IPV6_SUPPORT.md)
- [OAuth2](docs/protocols/OAUTH2.md), [HTTP/3](docs/protocols/HTTP3.md)
- Changelogs live in [docs/CHANGELOGS/](docs/CHANGELOGS/)

## License

AGPL-3.0. Network use counts as distribution, so if you run a modified version as
a service you have to publish your changes. See [LICENSE](LICENSE).
