# RhinoWAF

A Detailed Web Application Firewall (WAF) built in Go with adaptive protection against DDoS attacks, SQL injection, XSS, and other web threats.

## Features

- **DDoS Protection**: Layer 4 and Layer 7 rate limiting with IP blocking(Basic)
- **Input Sanitization**: SQL injection, XSS, and malicious input filtering  
- **Adaptive Middleware**: Combines all security features well
- **High Performance**: Fast RPS handling with modular architecture
- **Universal Protection**: Sanitizes URL params, form data, headers, and cookies

## Structure

```
RhinoWAF/
├── cmd/
│   └── rhinowaf/
│       └── main.go
├── handlers/
│   └── handlers.go
├── waf/
│   ├── adaptive.go
│   ├── ddos/
│   │   └── ddos.go
│   └── sanitize/
│       └── sanitize.go
├── go.mod
├── go.sum
└── README.md
```

- DDoS block (L7/L4)
- SQLi, XSS, encoding protection
- Universal input sanitizer
- Fast RPS, modular

Run:  
`go run cmd/rhinowaf/main.go`

## License

**AGPL-3.0 (Anti Skid)**

This project is licensed under the GNU Affero General Public License v3.0, which means:

- ✅ Free to use and modify
- ✅ Open source contributions welcome  
- ❌ **Skidders watch out!**: Any use (including web services) requires open sourcing your ENTIRE codebase
- ❌ Cannot be used in proprietary/closed-source applications
