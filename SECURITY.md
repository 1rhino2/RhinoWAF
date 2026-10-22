# Security Policy

## Supported versions

Only the latest 2.0.x release gets security fixes. Older tags are not patched.

| Version | Supported |
|---------|-----------|
| 2.0.x   | yes       |
| below 2.0 | no      |

## Reporting a vulnerability

Please do not open a public issue for a security bug.

Report it through the [RhinoWAF HackerOne program](https://hackerone.com/rhinowaf),
or use GitHub's private
[security advisory form](https://github.com/1rhino2/RhinoWAF/security/advisories/new)
if you would rather not make an account.

Useful in a report: the version or commit, your config (strip secrets), the
request that triggers it, and what you expected the WAF to do. A WAF bypass
needs the exact payload and the rule or detector it got past.

## What to expect

- First response within 7 days, usually faster.
- A fix or a clear decision within 30 days for confirmed issues.
- Credit in the release notes if you want it.

Bypasses of a detection rule on a non-default paranoia level, and findings that
need a hostile config or local root on the box, are low severity but still
welcome.

## Scope

In scope: the `waf/`, `handlers/`, and `cmd/` code in this repo, the default
config, and the release binaries.

Out of scope: the nginx, Caddy or Traefik in front of it, third-party challenge
providers (hCaptcha, Turnstile), and denial of service from raw volume that no
single host could absorb.
