package benchmarks

import (
	"net/http"
	"net/http/httptest"
	"rhinowaf/handlers"
	"rhinowaf/waf"
	"rhinowaf/waf/challenge"
	"rhinowaf/waf/csrf"
	"rhinowaf/waf/fingerprint"
	"rhinowaf/waf/requestid"
	"rhinowaf/waf/sanitize"
	"testing"
	"time"
)

// Baseline: no middleware
func BenchmarkNoMiddleware(b *testing.B) {
	handler := http.HandlerFunc(handlers.Home)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// Single middleware: Request ID only
func BenchmarkRequestIDMiddleware(b *testing.B) {
	handler := requestid.Middleware(http.HandlerFunc(handlers.Home))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// Single middleware: Sanitization only
func BenchmarkSanitizeMiddleware(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sanitize.All(r)
		handlers.Home(w, r)
	})
	req := httptest.NewRequest("GET", "/?name=test&email=test@example.com", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// Single middleware: CSRF protection
func BenchmarkCSRFMiddleware(b *testing.B) {
	csrfManager := csrf.NewManager(csrf.Config{
		Enabled:       true,
		TokenLength:   32,
		TokenTTL:      1 * time.Hour,
		CookieName:    "csrf_token",
		HeaderName:    "X-CSRF-Token",
		FormFieldName: "csrf_token",
		SecureCookie:  false,
		SameSite:      http.SameSiteLaxMode,
		ExemptMethods: []string{"GET", "HEAD", "OPTIONS"},
		ExemptPaths:   []string{"/health", "/metrics"},
	})
	csrfMW := csrf.NewMiddleware(csrfManager)
	handler := csrfMW.Handler(http.HandlerFunc(handlers.Home))
	
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// Single middleware: Fingerprint tracking
func BenchmarkFingerprintMiddleware(b *testing.B) {
	fpConfig := fingerprint.Config{
		Enabled:              true,
		MaxIPsPerFingerprint: 5,
		MaxAgeForReuse:       24 * time.Hour,
		SuspiciousThreshold:  3,
		BlockOnExceed:        false,
		RequireClientData:    false,
	}
	tracker := fingerprint.NewTracker(fpConfig)
	fpMW := fingerprint.NewMiddleware(tracker)
	handler := fpMW.Handler(http.HandlerFunc(handlers.Home))
	
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// Single middleware: Challenge system
func BenchmarkChallengeMiddleware(b *testing.B) {
	challengeMgr := challenge.NewManager()
	challengeConfig := challenge.Config{
		Enabled:         true,
		DefaultType:     challenge.TypeJavaScript,
		Difficulty:      4,
		WhitelistPaths:  []string{"/challenge/"},
		RequireForPaths: []string{},
	}
	challengeMW := challenge.NewMiddleware(challengeMgr, challengeConfig)
	handler := challengeMW.Handler(http.HandlerFunc(handlers.Home))
	
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// Stacked middlewares: Request ID + Sanitization
func BenchmarkTwoMiddlewares(b *testing.B) {
	handler := requestid.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sanitize.All(r)
		handlers.Home(w, r)
	}))
	
	req := httptest.NewRequest("GET", "/?name=test", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// Stacked middlewares: Request ID + CSRF + Sanitization
func BenchmarkThreeMiddlewares(b *testing.B) {
	csrfManager := csrf.NewManager(csrf.Config{
		Enabled:       true,
		TokenLength:   32,
		TokenTTL:      1 * time.Hour,
		ExemptMethods: []string{"GET", "HEAD", "OPTIONS"},
	})
	csrfMW := csrf.NewMiddleware(csrfManager)
	
	handler := requestid.Middleware(csrfMW.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sanitize.All(r)
		handlers.Home(w, r)
	})))
	
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// Full middleware stack: All protection layers
func BenchmarkFullMiddlewareStack(b *testing.B) {
	csrfManager := csrf.NewManager(csrf.Config{
		Enabled:       true,
		TokenLength:   32,
		TokenTTL:      1 * time.Hour,
		ExemptMethods: []string{"GET", "HEAD", "OPTIONS"},
	})
	csrfMW := csrf.NewMiddleware(csrfManager)
	
	fpConfig := fingerprint.Config{
		Enabled:              true,
		MaxIPsPerFingerprint: 5,
		MaxAgeForReuse:       24 * time.Hour,
		SuspiciousThreshold:  3,
		BlockOnExceed:        false,
	}
	tracker := fingerprint.NewTracker(fpConfig)
	fpMW := fingerprint.NewMiddleware(tracker)
	
	challengeMgr := challenge.NewManager()
	challengeConfig := challenge.Config{
		Enabled:         true,
		DefaultType:     challenge.TypeJavaScript,
		Difficulty:      4,
		WhitelistPaths:  []string{"/challenge/"},
	}
	challengeMW := challenge.NewMiddleware(challengeMgr, challengeConfig)
	
	handler := requestid.Middleware(
		csrfMW.Handler(
			fpMW.Handler(
				challengeMW.Handler(
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						sanitize.All(r)
						handlers.Home(w, r)
					}),
				),
			),
		),
	)
	
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// Full stack with WAF adaptive protection
func BenchmarkFullStackWithWAF(b *testing.B) {
	csrfManager := csrf.NewManager(csrf.Config{
		Enabled:       true,
		TokenLength:   32,
		TokenTTL:      1 * time.Hour,
		ExemptMethods: []string{"GET", "HEAD", "OPTIONS"},
	})
	csrfMW := csrf.NewMiddleware(csrfManager)
	
	fpConfig := fingerprint.Config{
		Enabled:              true,
		MaxIPsPerFingerprint: 5,
		MaxAgeForReuse:       24 * time.Hour,
	}
	tracker := fingerprint.NewTracker(fpConfig)
	fpMW := fingerprint.NewMiddleware(tracker)
	
	challengeMgr := challenge.NewManager()
	challengeConfig := challenge.Config{
		Enabled:     true,
		DefaultType: challenge.TypeJavaScript,
		Difficulty:  4,
	}
	challengeMW := challenge.NewMiddleware(challengeMgr, challengeConfig)
	
	handler := requestid.Middleware(
		csrfMW.Handler(
			fpMW.Handler(
				challengeMW.Handler(
					http.HandlerFunc(waf.AdaptiveProtect(handlers.Home)),
				),
			),
		),
	)
	
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// Parallel execution with full stack
func BenchmarkFullStackParallel(b *testing.B) {
	csrfManager := csrf.NewManager(csrf.Config{
		Enabled:       true,
		TokenLength:   32,
		TokenTTL:      1 * time.Hour,
		ExemptMethods: []string{"GET", "HEAD", "OPTIONS"},
	})
	csrfMW := csrf.NewMiddleware(csrfManager)
	
	fpConfig := fingerprint.Config{
		Enabled:              true,
		MaxIPsPerFingerprint: 5,
		MaxAgeForReuse:       24 * time.Hour,
	}
	tracker := fingerprint.NewTracker(fpConfig)
	fpMW := fingerprint.NewMiddleware(tracker)
	
	handler := requestid.Middleware(
		csrfMW.Handler(
			fpMW.Handler(
				http.HandlerFunc(waf.AdaptiveProtect(handlers.Home)),
			),
		),
	)
	
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.168.1.1:1234"
			req.Header.Set("User-Agent", "Mozilla/5.0")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}
