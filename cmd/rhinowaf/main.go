package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"rhinowaf/handlers"
	"rhinowaf/waf"
	"rhinowaf/waf/auth"
	"rhinowaf/waf/challenge"
	"rhinowaf/waf/csrf"
	"rhinowaf/waf/ddos"
	"rhinowaf/waf/fingerprint"
	"rhinowaf/waf/geo"
	"rhinowaf/waf/health"
	"rhinowaf/waf/http3"
	"rhinowaf/waf/logging"
	"rhinowaf/waf/oauth2"
	"rhinowaf/waf/reload"
	"rhinowaf/waf/reputation"
	"rhinowaf/waf/requestid"
	"rhinowaf/waf/vhost"
	"rhinowaf/waf/webhook"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	logWriter := logging.SetupRotation(logging.Config{
		Enabled:    true,
		Filename:   "./logs/rhinowaf.log",
		MaxSize:    100,
		MaxBackups: 3,
		MaxAge:     28,
		Compress:   true,
	})

	_ = ddos.InitLogger(&ddos.LoggerConfig{
		LogPath:              "./logs/ddos.log",
		Enabled:              true,
		LogToConsole:         true,
		MaxSizeMB:            100,
		MaxAgeDays:           30,
		CompressOld:          true,
		FlushInterval:        1 * time.Second,
		BatchSize:            100,
		HumanReadableEnabled: true,
		HumanReadablePath:    "./logs/ddos-readable.log",
	})

	log.SetOutput(logWriter)

	// webhook config - disabled by default, set URLs in config to enable
	webhook.Init(webhook.Config{
		Enabled:       false,
		URLs:          []string{},
		MinSeverity:   "high",
		Timeout:       5,
		MaxRetries:    2,
		SlackFormat:   false,
		DiscordFormat: false,
		TeamsFormat:   false,
	})

	// IP reputation - uses AbuseIPDB and IPQualityScore if keys are set
	reputation.Init(reputation.Config{
		Enabled:           false,
		Provider:          "both",
		AbuseIPDBKey:      os.Getenv("ABUSEIPDB_API_KEY"),
		IPQualityScoreKey: os.Getenv("IPQS_API_KEY"),
		CacheDuration:     60,
		ScoreThreshold:    75,
		AutoBlock:         false,
		AutoChallenge:     true,
		Timeout:           5,
	})

	// per-user rate limits with JWT
	auth.Init(auth.Config{
		Enabled:            false,
		JWTSecret:          os.Getenv("JWT_SECRET"),
		JWTHeader:          "Authorization",
		SessionCookie:      "session_id",
		RateLimitPerUser:   1000,
		RateLimitWindow:    60,
		WhitelistUsernames: []string{},
		TrackAnonymous:     false,
	})

	if err := ddos.InitIPManager("./config/ip_rules.json", true); err != nil {
		log.Printf("Warning: Could not initialize IP manager - %v (WAF will run with limited protection)", err)
	}

	// Load GeoIP database
	if err := geo.LoadGeoDatabase("./config/geoip.json"); err != nil {
		log.Printf("Warning: Could not load GeoIP database - %v (geolocation blocking will be unavailable)", err)
	}

	// Multi-vhost backend configuration
	vhostMgr, err := vhost.NewVHostManager("./config/backends.json")
	if err != nil {
		log.Printf("Warning: Could not initialize multi-vhost manager - %v (falling back to single backend)", err)
		vhostMgr = nil
	} else {
		stats := vhostMgr.GetStats()
		log.Printf("Multi-vhost enabled: %d domains configured", stats["total_backends"])
	}

	// hot-reload setup so we don't need to restart on config changes
	reloadMgr, err := reload.NewManager(reload.Config{
		IPRulesPath:  "./config/ip_rules.json",
		GeoDBPath:    "./config/geoip.json",
		DebounceTime: 2 * time.Second,
		WatchEnabled: true,
	})
	if err != nil {
		log.Printf("Warning: Could not initialize hot-reload system - %v (configuration changes will require restart)", err)
	}
	defer func() {
		if reloadMgr != nil {
			_ = reloadMgr.Stop()
		}
	}()

	// catch SIGHUP for manual config reload
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	go func() {
		for range sigChan {
			log.Println("Received SIGHUP signal, reloading all configurations...")
			if reloadMgr != nil {
				if err := reloadMgr.ReloadAll(); err != nil {
					log.Printf("Configuration reload failed: %v", err)
				} else {
					log.Println("All configurations reloaded successfully")
				}
			}
			if vhostMgr != nil {
				if err := vhostMgr.Reload("./config/backends.json"); err != nil {
					log.Printf("VHost reload failed: %v", err)
				}
			}
		}
	}()

	challengeMgr := challenge.NewManager()

	// setup captcha if env vars are set
	if hcaptchaKey := os.Getenv("HCAPTCHA_SITE_KEY"); hcaptchaKey != "" {
		secret := os.Getenv("HCAPTCHA_SECRET")
		if secret == "" {
			log.Printf("Warning: hCaptcha site key provided but secret is missing - hCaptcha challenges will not work")
		} else {
			challengeMgr.SetHCaptcha(hcaptchaKey, secret)
			log.Printf("hCaptcha configured successfully")
		}
	}
	if turnstileKey := os.Getenv("TURNSTILE_SITE_KEY"); turnstileKey != "" {
		secret := os.Getenv("TURNSTILE_SECRET")
		if secret == "" {
			log.Printf("Warning: Cloudflare Turnstile site key provided but secret is missing - Turnstile challenges will not work")
		} else {
			challengeMgr.SetTurnstile(turnstileKey, secret)
			log.Printf("Cloudflare Turnstile configured successfully")
		}
	}

	// fingerprint tracking - helps catch bot networks sharing fingerprints
	// TODO: might want to make BlockOnExceed=true in prod
	fingerprintConfig := fingerprint.Config{
		Enabled:              true,
		MaxIPsPerFingerprint: 5,
		MaxAgeForReuse:       24 * time.Hour,
		SuspiciousThreshold:  3,
		BlockOnExceed:        false,
		RequireClientData:    false,
	}
	fingerprintTracker := fingerprint.NewTracker(fingerprintConfig)
	fingerprintMW := fingerprint.NewMiddleware(fingerprintTracker)

	// CSRF protection
	csrfManager := csrf.NewManager(csrf.Config{
		Enabled:       true,
		TokenLength:   32,
		TokenTTL:      1 * time.Hour,
		CookieName:    "csrf_token",
		HeaderName:    "X-CSRF-Token",
		FormFieldName: "csrf_token",
		SecureCookie:  false, // flip to true when you add HTTPS
		SameSite:      http.SameSiteLaxMode,
		ExemptMethods: []string{"GET", "HEAD", "OPTIONS", "TRACE"},
		ExemptPaths: []string{
			"/health", "/metrics", "/challenge/", "/fingerprint/", "/csrf/token",
			"/api/webhooks", "/api/users", "/api/products", "/api/orders",
			"/api/data", "/api/v1/search",
			"/cart/", "/graphql",
		},
		DoubleSubmit: false,
		ErrorMessage: "CSRF validation failed",
	})
	csrfMW := csrf.NewMiddleware(csrfManager)

	// OAuth2 setup
	oauth2Handler := oauth2.NewHandler(oauth2.Config{
		Enabled:        false,
		ClientID:       os.Getenv("OAUTH2_CLIENT_ID"),
		ClientSecret:   os.Getenv("OAUTH2_CLIENT_SECRET"),
		AuthURL:        os.Getenv("OAUTH2_AUTH_URL"),
		TokenURL:       os.Getenv("OAUTH2_TOKEN_URL"),
		RedirectURL:    os.Getenv("OAUTH2_REDIRECT_URL"),
		Scopes:         []string{"openid", "email", "profile"},
		ProtectedPaths: []string{"/admin", "/api/protected"},
		SessionTimeout: 3600,
	})

	// HTTP/3 server setup (v2.4.1)
	http3Server := http3.NewServer(http3.Config{
		Enabled:      false, // disabled by default
		Port:         ":443",
		CertFile:     os.Getenv("HTTP3_CERT_FILE"),
		KeyFile:      os.Getenv("HTTP3_KEY_FILE"),
		MaxStreams:   100,
		IdleTimeout:  30,
		AltSvcHeader: true,
		Domains:      []string{},
	})

	// Configure challenge middleware
	challengeConfig := challenge.Config{
		Enabled:         true, // Challenge system enabled for high-risk traffic
		DefaultType:     challenge.TypeJavaScript,
		Difficulty:      5, // Moderate difficulty for proof-of-work challenges
		WhitelistPaths:  []string{"/challenge/"},
		RequireForPaths: []string{},
	}
	challengeMW := challenge.NewMiddleware(challengeMgr, challengeConfig)

	// Import localhost-only middleware
	importLocalhost := func(h http.Handler) http.Handler {
		return waf.LocalhostOnly(h)
	}

	mux := http.NewServeMux()

	// Sensitive endpoints: restrict to localhost
	mux.Handle("/metrics", importLocalhost(promhttp.Handler()))
	mux.Handle("/health", importLocalhost(http.HandlerFunc(health.Handler("v2.4.1"))))
	mux.Handle("/reload", importLocalhost(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST requests are accepted for configuration reload", http.StatusMethodNotAllowed)
			return
		}
		if reloadMgr == nil {
			http.Error(w, "Hot-reload system is not available", http.StatusInternalServerError)
			return
		}
		log.Println("Configuration reload requested via /reload endpoint")
		if err := reloadMgr.ReloadAll(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  err.Error(),
			})
			return
		}
		status := reloadMgr.GetStatus()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"config": status,
		})
	})))
	mux.Handle("/fingerprint/collect", importLocalhost(http.HandlerFunc(fingerprintMW.CollectHandler)))
	mux.Handle("/fingerprint/stats", importLocalhost(http.HandlerFunc(fingerprintMW.StatsHandler)))
	mux.Handle("/csrf/token", importLocalhost(http.HandlerFunc(csrfMW.TokenHandler)))
	
	// VHost stats endpoint
	if vhostMgr != nil {
		mux.Handle("/vhost/stats", importLocalhost(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stats := vhostMgr.GetStats()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(stats)
		})))
	}

	// Challenge verification endpoint (still public, but can restrict if needed)
	mux.HandleFunc("/challenge/verify", challengeMW.VerifyHandler)

	// Multi-vhost routing or fallback to default handlers
	if vhostMgr != nil {
		// Use vhost manager for routing to different backends
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			vhostMgr.ServeHTTP(w, r)
		})
	} else {
		// Fallback to single backend with static handlers
		mux.HandleFunc("/", waf.AdaptiveProtect(handlers.Home))
		mux.HandleFunc("/api/", waf.AdaptiveProtect(handlers.APIHandler))
		mux.HandleFunc("/about", waf.AdaptiveProtect(handlers.AboutHandler))
		mux.HandleFunc("/contact", waf.AdaptiveProtect(handlers.ContactHandler))
		mux.HandleFunc("/login", waf.AdaptiveProtect(handlers.Login))
		mux.HandleFunc("/echo", waf.AdaptiveProtect(handlers.Echo))
		mux.Handle("/flood", importLocalhost(http.HandlerFunc(handlers.Flood)))
	}

	// Apply middleware layers: request ID -> oauth2 -> csrf -> fingerprint -> challenge -> routes
	handler := requestid.Middleware(oauth2Handler.Handle(csrfMW.Handler(fingerprintMW.Handler(challengeMW.Handler(mux)))))

	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   RhinoWAF v2.4.1                          ║")
	fmt.Println("║                    Starting up                             ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println("")
	fmt.Println("  Active Security Features:")
	fmt.Println("   - DDoS Protection with Adaptive Rate Limiting")
	fmt.Println("   - Advanced IP Rules (60+ configurable fields)")
	fmt.Println("   - Challenge System (JavaScript and Proof-of-Work)")
	fmt.Println("   - Browser Fingerprinting for Bot Detection")
	fmt.Println("   - CSRF Protection with Token Validation")
	fmt.Println("   - Geolocation-based Access Control")
	fmt.Println("   - Proxy, Tor, and VPN Detection")
	fmt.Println("   - Input Sanitization and XSS Protection")
	fmt.Println("   - Live Configuration Reloading")
	fmt.Println("")
	fmt.Println("  Quality of Life Features (v2.3.1):")
	fmt.Println("   - Custom Error Pages with Branding")
	fmt.Println("   - Webhook Notifications (Slack/Discord/Teams)")
	fmt.Println("   - IP Reputation Checking (AbuseIPDB/IPQualityScore)")
	fmt.Println("   - Connection Pooling for Backend Proxy")
	fmt.Println("   - Automatic Log Rotation and Compression")
	fmt.Println("   - JWT/Session-based Rate Limiting")
	fmt.Println("")
	fmt.Println("  Service Information:")
	fmt.Println("   WAF is listening on http://localhost:8080")
	fmt.Println("   Health check endpoint at /health")
	fmt.Println("   Prometheus metrics available at /metrics")
	fmt.Println("   Configuration reload endpoint at /reload (POST)")

	// Start HTTP/3 server if enabled
	if http3Server.IsRunning() || os.Getenv("HTTP3_ENABLED") == "true" {
		if err := http3Server.Start(handler); err != nil {
			log.Printf("[HTTP/3] Failed to start: %v", err)
		}
	}
	fmt.Println("   Automatic file watching is active")
	fmt.Println("   Manual reload available with: kill -SIGHUP <pid>")
	fmt.Println("   Attack logs being written to ./logs/ddos.log")
	fmt.Println("   General logs being written to ./logs/rhinowaf.log")
	fmt.Println("   Backend proxy target: http://localhost:9000")
	fmt.Println("")
	fmt.Println("RhinoWAF is ready and protecting your application.")
	fmt.Println("")

	log.Fatal(http.ListenAndServe(":8080", handler))
}
