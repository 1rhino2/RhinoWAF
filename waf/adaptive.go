package waf

import (
	"net/http"
	"rhinowaf/waf/ddos"
	"rhinowaf/waf/sanitize"
	"rhinowaf/waf/templates"
	"time"
)

func AdaptiveProtect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := ddos.GetIP(r)

		// validate headers first (prevents header injection)
		if valid, reason := sanitize.ValidateHeaders(r); !valid {
			templates.RenderBlockedError(w, ip, reason)
			return
		}

		// check IP rules (most specific)
		ipMgr := ddos.GetIPManager()
		if ipMgr != nil {
			ctx := &ddos.RequestContext{
				IP:            ip,
				Path:          r.URL.Path,
				FullURL:       r.URL.String(),
				Method:        r.Method,
				UserAgent:     r.UserAgent(),
				Referer:       r.Referer(),
				ContentType:   r.Header.Get("Content-Type"),
				ContentLength: r.ContentLength,
				Protocol:      r.Proto,
				IsHTTPS:       r.TLS != nil,
				Timestamp:     time.Now(),
				Headers:       make(map[string]string),
				Cookies:       make(map[string]string),
				QueryParams:   make(map[string]string),
			}

			// Copy headers
			for key, values := range r.Header {
				if len(values) > 0 {
					ctx.Headers[key] = values[0]
				}
			}

			// Copy cookies
			for _, cookie := range r.Cookies() {
				ctx.Cookies[cookie.Name] = cookie.Value
			}

			// Copy query params
			for key, values := range r.URL.Query() {
				if len(values) > 0 {
					ctx.QueryParams[key] = values[0]
				}
			}

			allowed, reason := ipMgr.ValidateRequest(ctx)
			if !allowed {
				templates.RenderBlockedError(w, ip, reason)
				return
			}
		}

		// Whitelist legitimate API clients from rate limiting
		// These are trusted automated services that may make frequent requests
		ua := r.UserAgent()
		uaLower := ""
		for _, c := range ua {
			if c >= 'A' && c <= 'Z' {
				uaLower += string(c + 32)
			} else {
				uaLower += string(c)
			}
		}

		trustedClients := []string{
			"github-hookshot", "stripe-signature", "stripe", "twilio", "slack",
			"googlebot", "bingbot", "slurp", "duckduckbot",
		}
		isTrusted := false
		for _, client := range trustedClients {
			if len(uaLower) >= len(client) {
				for i := 0; i <= len(uaLower)-len(client); i++ {
					if uaLower[i:i+len(client)] == client {
						isTrusted = true
						break
					}
				}
			}
			if isTrusted {
				break
			}
		}

		// Check rate limits (L7/L4) unless trusted client
		if !isTrusted && (!ddos.AllowL7(ip) || !ddos.AllowL4(ip)) {
			templates.RenderRateLimitError(w, ip)
			return
		} // Check for malicious input FIRST (before sanitization removes patterns)
		if sanitize.IsMalicious(r) {
			templates.RenderMaliciousError(w)
			return
		}

		// Then sanitize all input before passing to backend
		sanitize.All(r)

		next(w, r)
	}
}
