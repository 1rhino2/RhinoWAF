package waf

import (
	"context"
	"net/http"
	"rhinowaf/waf/autoban"
	"rhinowaf/waf/cookie"
	"rhinowaf/waf/ddos"
	"rhinowaf/waf/engine"
	"rhinowaf/waf/requestid"
	"rhinowaf/waf/sanitize"
	"rhinowaf/waf/smuggling"
	"rhinowaf/waf/templates"
	"rhinowaf/waf/websocket"
	"strings"
	"time"
)

type ctxKey int

const protectedKey ctxKey = 1

var (
	globalWSHandler      *websocket.Handler
	globalSmuggleChecker *smuggling.Detector
	globalAutoBan        *autoban.Tracker
	globalCookieSigner   *cookie.Signer
)

// SetAutoBan installs the persistent auto-ban tracker built in main. Repeat
// offenders (engine blocks) get a temporary IP ban that outlives a restart.
func SetAutoBan(t *autoban.Tracker) { globalAutoBan = t }

// SetCookieSigner installs the process cookie signer (challenge/fingerprint
// passes). Exposed so challenge and fingerprint middleware share one key.
func SetCookieSigner(s *cookie.Signer) { globalCookieSigner = s }

// CookieSigner returns the shared signer, may be nil before main sets it.
func CookieSigner() *cookie.Signer { return globalCookieSigner }

// SetWebSocketHandler swaps in the handler built from features.json. Without
// this the websocket section only fed the stats endpoint and enforcement ran
// on the hardcoded defaults below.
func SetWebSocketHandler(h *websocket.Handler) {
	if h != nil {
		globalWSHandler = h
	}
}

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

// ProtectMiddleware runs ProtectRequest before fingerprint/challenge so attacks
// get blocked instead of a verification HTML page.
func ProtectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if skipProtectPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if !ProtectRequest(w, r) {
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), protectedKey, true)))
	})
}

func skipProtectPath(path string) bool {
	switch {
	case path == "/health", path == "/metrics", path == "/reload":
		return true
	case strings.HasPrefix(path, "/challenge/"):
		return true
	case path == "/fingerprint/stats", path == "/websocket/stats", path == "/vhost/stats":
		return true
	default:
		return false
	}
}

// ProtectRequest runs rate limits, IP rules, smuggling checks, and sanitization.
// Returns true when the request may continue to the backend handler.
func ProtectRequest(w http.ResponseWriter, r *http.Request) bool {
	// already cleared by ProtectMiddleware - don't burn a second rate-limit token
	if r.Context().Value(protectedKey) != nil {
		return true
	}

	ip := ddos.GetIP(r)

	// an auto-banned repeat offender is dropped before we spend work on it
	if globalAutoBan != nil && globalAutoBan.IsBanned(ip) {
		templates.RenderBlockedError(w, ip, "temporarily banned for repeated violations")
		return false
	}

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

	// detection: the engine is the gate when enabled, the legacy sanitizer
	// is the fallback for anyone who turns it off.
	if engine.Active() {
		eng := engine.Default()
		v := eng.Inspect(r)
		eng.LogEvent(v, requestid.FromRequest(r), ip, r.Host, r.Method, r.URL.Path)
		if v.Blocked() {
			rules := ""
			if len(v.Evidence) > 0 {
				rules = v.RuleIDs()
			}
			if globalAutoBan != nil {
				globalAutoBan.RecordViolation(ip, v.Summary())
			}
			templates.RenderEngineBlock(w, ip, requestid.FromRequest(r), v.Summary(), rules)
			return false
		}
	} else if sanitize.IsMalicious(r) {
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
