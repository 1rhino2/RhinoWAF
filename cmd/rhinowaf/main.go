package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"rhinowaf/handlers"
	"rhinowaf/waf"
	"rhinowaf/waf/auth"
	"rhinowaf/waf/autoban"
	"rhinowaf/waf/challenge"
	"rhinowaf/waf/config"
	"rhinowaf/waf/csrf"
	"rhinowaf/waf/ddos"
	"rhinowaf/waf/engine"
	"rhinowaf/waf/fingerprint"
	"rhinowaf/waf/geo"
	"rhinowaf/waf/health"
	"rhinowaf/waf/http3"
	"rhinowaf/waf/logging"
	"rhinowaf/waf/oauth2"
	"rhinowaf/waf/reload"
	"rhinowaf/waf/reputation"
	"rhinowaf/waf/requestid"
	"rhinowaf/waf/security"
	"rhinowaf/waf/state"
	enginestate "rhinowaf/waf/statewire"
	"rhinowaf/waf/templates"
	"rhinowaf/waf/vhost"
	"rhinowaf/waf/webhook"
	"rhinowaf/waf/websocket"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Overridden at link time in CI builds.
var (
	Version   = waf.Version
	BuildTime = "dev"
)

// envOr returns flagVal if set, else the env var, else def. Precedence is
// flag > env > default, which is what people expect from a 12-factor service.
func envOr(flagVal, envKey, def string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return def
}

// relToCfg resolves a rules dir relative to the config dir. empty stays empty
// (meaning "use the embedded set" / "no extra dir").
func relToCfg(cfgDir, dir string) string {
	if dir == "" {
		return ""
	}
	if filepath.IsAbs(dir) {
		return dir
	}
	return filepath.Join(cfgDir, dir)
}

func main() {
	var (
		showVersion = flag.Bool("version", false, "print version and exit")
		configDir   = flag.String("config-dir", "", "directory holding ip_rules.json, geoip.json, backends.json, features.json (env RHINOWAF_CONFIG_DIR, default ./config)")
		logDir      = flag.String("log-dir", "", "directory for log files (env RHINOWAF_LOG_DIR, default ./logs)")
		listenFlag  = flag.String("listen", "", "address to listen on, e.g. :8080 or 127.0.0.1:8080 (env RHINOWAF_LISTEN, overrides features.json)")
		backendFlag = flag.String("backend", "", "fallback backend URL when no backends.json (env RHINOWAF_BACKEND, overrides features.json)")
		featuresArg = flag.String("features", "", "path to features.json (env RHINOWAF_FEATURES, default <config-dir>/features.json)")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s %s (built %s)\n", waf.Name, Version, BuildTime)
		return
	}

	cfgDir := envOr(*configDir, "RHINOWAF_CONFIG_DIR", "./config")
	lgDir := envOr(*logDir, "RHINOWAF_LOG_DIR", "./logs")
	featuresPath := envOr(*featuresArg, "RHINOWAF_FEATURES", filepath.Join(cfgDir, "features.json"))

	// features.json drives the app-level middleware. A missing file just uses
	// the built-in defaults; a broken file stops us here on purpose so a typo
	// never silently drops protection.
	cfg, err := config.Load(featuresPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	// flag/env win over the file for the couple of knobs people flip most.
	listenAddr := envOr(*listenFlag, "RHINOWAF_LISTEN", cfg.Server.Listen)
	backendURL := envOr(*backendFlag, "RHINOWAF_BACKEND", cfg.Backend.ProxyURL)

	templates.BrandVersion = Version

	// which upstream proxies may set X-Forwarded-For; empty keeps the
	// loopback/private default
	if len(cfg.Server.TrustedProxies) > 0 {
		if err := security.SetTrustedProxies(cfg.Server.TrustedProxies); err != nil {
			log.Fatalf("config error: trusted_proxies: %v", err)
		}
	}

	logWriter := logging.SetupRotation(logging.Config{
		Enabled:    cfg.Logging.Enabled,
		Filename:   filepath.Join(lgDir, "rhinowaf.log"),
		MaxSize:    cfg.Logging.MaxSizeMB,
		MaxBackups: cfg.Logging.MaxBackups,
		MaxAge:     cfg.Logging.MaxAgeDays,
		Compress:   cfg.Logging.Compress,
	})
	log.SetOutput(logWriter)

	_ = ddos.InitLogger(&ddos.LoggerConfig{
		LogPath:              filepath.Join(lgDir, "ddos.log"),
		Enabled:              cfg.Logging.Enabled,
		LogToConsole:         true,
		MaxSizeMB:            cfg.Logging.MaxSizeMB,
		MaxAgeDays:           cfg.Logging.MaxAgeDays,
		CompressOld:          cfg.Logging.Compress,
		FlushInterval:        1 * time.Second,
		BatchSize:            100,
		HumanReadableEnabled: true,
		HumanReadablePath:    filepath.Join(lgDir, "ddos-readable.log"),
	})

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

	// detection engine: embedded default rules, optionally replaced by
	// engine.rules_dir and layered with engine.extra_rules_dir, both relative
	// to the config dir. a bad ruleset stops us here, same as a bad config.
	engLoader := engine.Loader{
		RulesDir: relToCfg(cfgDir, cfg.Engine.RulesDir),
		ExtraDir: relToCfg(cfgDir, cfg.Engine.ExtraRulesDir),
	}
	engRuleset, err := engLoader.Load()
	if err != nil {
		log.Fatalf("engine: %v", err)
	}
	eng := engine.New(cfg.Engine, engRuleset)
	if cfg.Logging.Enabled {
		eng.SetSink(engine.NewFileSink(filepath.Join(lgDir, "engine.log"),
			cfg.Logging.MaxSizeMB, cfg.Logging.MaxAgeDays, cfg.Logging.MaxBackups, cfg.Logging.Compress))
	}
	engine.SetDefault(eng)
	if rs := eng.Ruleset(); rs != nil {
		log.Printf("engine: %d rules loaded (ruleset %s), mode=%s paranoia=%d", rs.RuleCount(), rs.Hash(), cfg.Engine.Mode, cfg.Engine.Paranoia)
	}

	// persistent state: bans, the cookie signing key, reputation cache. a
	// missing or unwritable file just runs in memory (see waf/state).
	statePath := cfg.State.Path
	if statePath == "" {
		statePath = filepath.Join(lgDir, "rhinowaf.db")
	}
	var stateDB *state.DB
	if cfg.State.Enabled {
		stateDB = state.Open(statePath)
		defer func() { _ = stateDB.Close() }()
		if stateDB.Persistent() {
			log.Printf("state: persisting to %s", stateDB.Path())
		} else {
			log.Printf("state: running in memory (could not open %s)", statePath)
		}
	}

	// cookie signer: reuse the persisted key so challenge/fingerprint passes
	// survive a restart, generate and store one on first run.
	cookieSigner := enginestate.SignerFromState(stateDB)
	waf.SetCookieSigner(cookieSigner)

	// auto-ban repeat offenders, persisted so a ban outlives a restart.
	autoBan := autoban.NewTracker(autoban.Config{
		Enabled:        cfg.AutoBan.Enabled,
		ViolationLimit: cfg.AutoBan.Threshold,
		WindowDuration: time.Duration(cfg.AutoBan.WindowSeconds) * time.Second,
		BanDuration:    time.Duration(cfg.AutoBan.BanMinutes) * time.Minute,
		PermanentAfter: 1000000, // temp bans only, escalation is a later feature
	})
	autoBan.SetPersist(enginestate.BanStore{DB: stateDB})
	autoBan.OnBan(func(ip, reason string, until time.Time) {
		dur := time.Until(until)
		if dur <= 0 {
			dur = time.Duration(cfg.AutoBan.BanMinutes) * time.Minute
		}
		if mgr := ddos.GetIPManager(); mgr != nil {
			_ = mgr.AutoBanIP(ip, "autoban: "+reason, dur)
		}
		webhook.Send(webhook.AttackEvent{EventType: "autoban", IP: ip, Severity: "critical", Message: "auto-banned repeat offender", Details: reason, Action: "blocked"})
		log.Printf("[AUTOBAN] %s banned for %s (%s)", ip, dur.Round(time.Second), reason)
	})
	waf.SetAutoBan(autoBan)

	ipRulesPath := filepath.Join(cfgDir, "ip_rules.json")
	geoDBPath := filepath.Join(cfgDir, "geoip.json")
	backendsPath := filepath.Join(cfgDir, "backends.json")

	if err := ddos.InitIPManager(ipRulesPath, true); err != nil {
		log.Printf("Warning: Could not initialize IP manager - %v (WAF will run with limited protection)", err)
	}

	if err := geo.LoadGeoDatabase(geoDBPath); err != nil {
		log.Printf("Warning: Could not load GeoIP database - %v (geolocation blocking will be unavailable)", err)
	}

	// Multi-vhost backend configuration
	vhostMgr, err := vhost.NewVHostManager(backendsPath)
	if err != nil {
		log.Printf("Warning: Could not initialize multi-vhost manager - %v (falling back to single backend)", err)
		vhostMgr = nil
	} else {
		stats := vhostMgr.GetStats()
		log.Printf("Multi-vhost enabled: %d domains configured", stats["total_backends"])
	}

	// single-backend fallback proxy (only used when there is no backends.json)
	if vhostMgr == nil {
		if err := handlers.Configure(backendURL, cfg.Backend.MaxIdleConns); err != nil {
			log.Printf("Warning: invalid backend URL %q - %v (keeping default)", backendURL, err)
		}
	}

	// hot-reload setup so we don't need to restart on config changes
	reloadMgr, err := reload.NewManager(reload.Config{
		IPRulesPath:  ipRulesPath,
		GeoDBPath:    geoDBPath,
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
				if err := vhostMgr.Reload(backendsPath); err != nil {
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
	fingerprintConfig := fingerprint.Config{
		Enabled:              cfg.Fingerprint.Enabled,
		MaxIPsPerFingerprint: cfg.Fingerprint.MaxIPsPerFingerprint,
		MaxAgeForReuse:       time.Duration(cfg.Fingerprint.MaxAgeHours) * time.Hour,
		SuspiciousThreshold:  cfg.Fingerprint.SuspiciousThreshold,
		BlockOnExceed:        cfg.Fingerprint.BlockOnExceed,
		RequireClientData:    cfg.Fingerprint.RequireClientData,
		CollectionRateLimit:  cfg.Fingerprint.CollectionRateLimit,
	}
	fingerprintTracker := fingerprint.NewTracker(fingerprintConfig)
	fingerprintMW := fingerprint.NewMiddleware(fingerprintTracker)

	// WebSocket security
	websocketHandler := websocket.NewHandler(websocket.Config{
		Enabled:              cfg.WebSocket.Enabled,
		MaxConnectionsPerIP:  cfg.WebSocket.MaxConnectionsPerIP,
		ConnectionRateLimit:  cfg.WebSocket.ConnectionRateLimit,
		ConnectionRateWindow: time.Duration(cfg.WebSocket.ConnectionRateWindowSeconds) * time.Second,
		MaxMessageSize:       cfg.WebSocket.MaxMessageSize,
		MessageRateLimit:     cfg.WebSocket.MessageRateLimit,
		MessageRateWindow:    time.Duration(cfg.WebSocket.MessageRateWindowSeconds) * time.Second,
		AllowedOrigins:       cfg.WebSocket.AllowedOrigins,
		AllowOriginWildcard:  cfg.WebSocket.AllowOriginWildcard,
		BlockBinaryMessages:  cfg.WebSocket.BlockBinaryMessages,
		MaxViolations:        cfg.WebSocket.MaxViolations,
		ViolationBanDuration: time.Duration(cfg.WebSocket.ViolationBanDurationMinutes) * time.Minute,
		IdleTimeout:          time.Duration(cfg.WebSocket.IdleTimeoutMinutes) * time.Minute,
		HandshakeTimeout:     time.Duration(cfg.WebSocket.HandshakeTimeoutSeconds) * time.Second,
	})
	waf.SetWebSocketHandler(websocketHandler)

	// CSRF protection, opt-in via features.json since the backend has to
	// cooperate (fetch /csrf/token, send it back)
	csrfManager := csrf.NewManager(csrf.Config{
		Enabled:       cfg.CSRF.Enabled,
		TokenLength:   32,
		TokenTTL:      time.Duration(cfg.CSRF.TokenTTLHours) * time.Hour,
		CookieName:    "csrf_token",
		HeaderName:    "X-CSRF-Token",
		FormFieldName: "csrf_token",
		SecureCookie:  cfg.CSRF.SecureCookie,
		SameSite:      http.SameSiteLaxMode,
		ExemptMethods: []string{"GET", "HEAD", "OPTIONS", "TRACE"},
		// the WAF's own endpoints must never be gated, whatever the user lists
		ExemptPaths:  append(cfg.CSRF.ExemptPaths, "/challenge/", "/fingerprint/", "/csrf/token"),
		DoubleSubmit: cfg.CSRF.DoubleSubmit,
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

	// HTTP/3 server setup, HTTP3_ENABLED=true plus cert/key env turns it on
	http3Server := http3.NewServer(http3.Config{
		Enabled:      os.Getenv("HTTP3_ENABLED") == "true",
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
		Enabled:         cfg.Challenge.Enabled,
		DefaultType:     challenge.ChallengeType(cfg.Challenge.DefaultType),
		Difficulty:      cfg.Challenge.PowDifficulty,
		WhitelistPaths:  cfg.Challenge.WhitelistPaths,
		RequireForPaths: cfg.Challenge.RequireForPaths,
	}
	challengeMW := challenge.NewMiddleware(challengeMgr, challengeConfig)
	challengeMW.SetSigner(cookieSigner, time.Duration(cfg.Challenge.PassTTLHours)*time.Hour)

	// Import localhost-only middleware
	importLocalhost := func(h http.Handler) http.Handler {
		return waf.LocalhostOnly(h)
	}

	mux := http.NewServeMux()

	// Sensitive endpoints: restrict to localhost
	mux.Handle("/metrics", importLocalhost(promhttp.Handler()))
	mux.Handle("/health", importLocalhost(http.HandlerFunc(health.Handler(Version))))
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
		// SIGHUP reloaded vhosts too, the HTTP path forgot to
		if vhostMgr != nil {
			if err := vhostMgr.Reload(backendsPath); err != nil {
				log.Printf("VHost reload failed: %v", err)
			}
		}
		status := reloadMgr.GetStatus()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"config": status,
		})
	})))
	// browsers POST here from the verification page, so it has to be public.
	// it is rate limited per IP inside CollectHandler.
	mux.HandleFunc("/fingerprint/collect", fingerprintMW.CollectHandler)
	mux.Handle("/fingerprint/stats", importLocalhost(http.HandlerFunc(fingerprintMW.StatsHandler)))
	// same story, the frontend fetches its token from here
	mux.HandleFunc("/csrf/token", csrfMW.TokenHandler)
	mux.Handle("/websocket/stats", importLocalhost(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stats := websocketHandler.GetStats()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stats)
	})))

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
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			vhostMgr.ServeHTTP(w, r)
		})
	} else {
		// everything goes to the backend. /login and /echo used to hit demo
		// handlers here, which hijacked those paths on real apps.
		mux.HandleFunc("/", waf.AdaptiveProtect(handlers.Home))
		mux.Handle("/flood", importLocalhost(http.HandlerFunc(handlers.Flood)))
	}

	// protect first so attacks never get fingerprint HTML instead of a block
	handler := requestid.Middleware(waf.ProtectMiddleware(oauth2Handler.Handle(csrfMW.Handler(fingerprintMW.Handler(challengeMW.Handler(mux))))))

	printBanner(Version, listenAddr, backendURL, lgDir, vhostMgr != nil)

	// Start HTTP/3 server if enabled
	if http3Server.IsRunning() || os.Getenv("HTTP3_ENABLED") == "true" {
		if err := http3Server.Start(handler); err != nil {
			log.Printf("[HTTP/3] Failed to start: %v", err)
		}
	}

	// real timeouts so the WAF's own listener isn't a slowloris target
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: time.Duration(cfg.Server.ReadHeaderTimeoutSeconds) * time.Second,
		ReadTimeout:       time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second,
		WriteTimeout:      time.Duration(cfg.Server.WriteTimeoutSeconds) * time.Second,
		IdleTimeout:       time.Duration(cfg.Server.IdleTimeoutSeconds) * time.Second,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}

	// graceful shutdown: drain in-flight requests on Ctrl-C / SIGTERM
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("Shutdown signal received, draining connections...")
		fmt.Println("\nShutting down RhinoWAF, draining in-flight requests...")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Graceful shutdown failed, forcing close: %v", err)
			_ = srv.Close()
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
	log.Println("RhinoWAF stopped")
	fmt.Println("RhinoWAF stopped cleanly.")
}

func printBanner(version, listenAddr, backendURL, logDir string, vhostMode bool) {
	fmt.Println("==============================================================")
	fmt.Printf("  RhinoWAF %s - starting up\n", version)
	fmt.Println("==============================================================")
	fmt.Println()
	fmt.Println("  Active protection:")
	fmt.Println("   - DDoS / rate limiting with adaptive limits")
	fmt.Println("   - IP rules (per-IP controls) and geo / ASN blocking")
	fmt.Println("   - Challenge system (JavaScript and proof-of-work)")
	fmt.Println("   - Browser fingerprinting for bot-network detection")
	fmt.Println("   - CSRF token validation")
	fmt.Println("   - WebSocket connection and message limits")
	fmt.Println("   - HTTP request smuggling detection")
	fmt.Println("   - Input sanitization (SQLi / XSS / traversal / injection)")
	fmt.Println("   - Live config reload (auto file-watch + SIGHUP)")
	fmt.Println()
	fmt.Println("  Listening:")
	fmt.Printf("   - WAF:        http://%s\n", displayAddr(listenAddr))
	fmt.Printf("   - Health:     http://%s/health (localhost only)\n", displayAddr(listenAddr))
	fmt.Printf("   - Metrics:    http://%s/metrics (localhost only)\n", displayAddr(listenAddr))
	fmt.Printf("   - Reload:     POST http://%s/reload (localhost only)\n", displayAddr(listenAddr))
	if vhostMode {
		fmt.Println("   - Routing:    multi-vhost (config/backends.json)")
	} else {
		fmt.Printf("   - Backend:    %s\n", backendURL)
	}
	fmt.Printf("   - Logs:       %s\n", logDir)
	fmt.Println("   - Reload cmd: kill -SIGHUP <pid>")
	fmt.Println()
	fmt.Println("RhinoWAF is ready and protecting your application.")
	fmt.Println()
}

// displayAddr turns ":8080" into "localhost:8080" for a clickable banner line.
func displayAddr(addr string) string {
	if len(addr) > 0 && addr[0] == ':' {
		return "localhost" + addr
	}
	return addr
}
