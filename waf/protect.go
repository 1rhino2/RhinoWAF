package waf

import (
	"net/http"
	"rhinowaf/waf/ddos"
	"rhinowaf/waf/sanitize"
	"rhinowaf/waf/smuggling"
	"rhinowaf/waf/templates"
	"rhinowaf/waf/websocket"
	"strings"
	"time"
)

var (
	globalWSHandler      *websocket.Handler
	globalSmuggleChecker *smuggling.Detector
)

func init() {
	globalWSHandler = websocket.NewHandler(websocket.Config{
		Enabled:              true,
		MaxConnectionsPerIP:  10,
		ConnectionRateLimit:  5,
		ConnectionRateWindow: time.Minute,
		MaxMessageSize:       1024 * 1024,
		MessageRateLimit:     100,
		MessageRateWindow:    time.Minute,
		AllowOriginWildcard:  true,
		BlockBinaryMessages:  false,
		MaxViolations:        5,
		ViolationBanDuration: 30 * time.Minute,
		IdleTimeout:          5 * time.Minute,
		HandshakeTimeout:     10 * time.Second,
	})
	globalSmuggleChecker = smuggling.NewDetector(true, true, 4)
}

// ProtectRequest runs rate limits, IP rules, smuggling checks, and sanitization.
// Returns true when the request may continue to the backend handler.
func ProtectRequest(w http.ResponseWriter, r *http.Request) bool {
	ip := ddos.GetIP(r)

	if valid, reason := sanitize.ValidateHeaders(r); !valid {
		templates.RenderBlockedError(w, ip, reason)
		return false
	}

	if violations, blocked := globalSmuggleChecker.Check(r); blocked {
		reason := "HTTP request smuggling detected"
		if len(violations) > 0 {
			reason = violations[0].Description
		}
		templates.RenderBlockedError(w, ip, reason)
		return false
	}

	if allowed, reason := globalWSHandler.ValidateUpgrade(r, ip); !allowed {
		templates.RenderBlockedError(w, ip, reason)
		return false
	}

	ipMgr := ddos.GetIPManager()
	if ipMgr != nil {
		ctx := buildRequestContext(r, ip)
		allowed, reason := ipMgr.ValidateRequest(ctx)
		if !allowed {
			templates.RenderBlockedError(w, ip, reason)
			return false
		}
	}

	if !isTrustedClient(r.UserAgent()) {
		if !ddos.AllowL7(ip) || !ddos.AllowL4(ip) {
			templates.RenderRateLimitError(w, ip)
			return false
		}
	}

	if sanitize.IsMalicious(r) {
		templates.RenderMaliciousError(w)
		return false
	}

	sanitize.All(r)
	return true
}

func buildRequestContext(r *http.Request, ip string) *ddos.RequestContext {
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

	for key, values := range r.Header {
		if len(values) > 0 {
			ctx.Headers[key] = values[0]
		}
	}
	for _, cookie := range r.Cookies() {
		ctx.Cookies[cookie.Name] = cookie.Value
	}
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			ctx.QueryParams[key] = values[0]
		}
	}
	return ctx
}

func isTrustedClient(ua string) bool {
	uaLower := strings.ToLower(ua)
	trustedClients := []string{
		"github-hookshot", "stripe-signature", "stripe", "twilio", "slack",
		"googlebot", "bingbot", "slurp", "duckduckbot",
	}
	for _, client := range trustedClients {
		if strings.Contains(uaLower, client) {
			return true
		}
	}
	return false
}
