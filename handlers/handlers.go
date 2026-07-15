package handlers

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"rhinowaf/waf"
	"rhinowaf/waf/ddos"
	"rhinowaf/waf/websocket"
	"time"
)

// Backend server URL
const backendURL = "http://localhost:9000"

// ReverseProxy handles proxying requests to the backend
var proxy *httputil.ReverseProxy
var wsHandler *websocket.Handler

func init() {
	// Initialize WebSocket security handler
	wsHandler = websocket.NewHandler(websocket.Config{
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
	target, _ := url.Parse(backendURL)

	// Create custom transport with connection pooling
	transport := &http.Transport{
		MaxIdleConns:        100,              // Max idle connections across all hosts
		MaxIdleConnsPerHost: 10,               // Max idle connections per host
		IdleConnTimeout:     90 * time.Second, // How long idle connections stay open
		DisableKeepAlives:   false,            // Enable keep-alive
		DisableCompression:  false,            // Enable compression
	}

	proxy = httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		fmt.Fprintf(w, "Unable to connect to backend server. Please try again in a moment.")
	}
}

// ProxyToBackend forwards requests to the backend application
func ProxyToBackend(w http.ResponseWriter, r *http.Request) {
	// Check WebSocket upgrade attempts
	ip := ddos.GetIP(r)
	if allowed, reason := wsHandler.ValidateUpgrade(r, ip); !allowed {
		http.Error(w, reason, http.StatusForbidden)
		return
	}

	// Add headers to indicate the request passed through WAF
	r.Header.Set("X-Protected-By", waf.Name+"-"+waf.Version)
	r.Header.Set("X-WAF-Status", "PASSED")

	// Proxy the request
	proxy.ServeHTTP(w, r)
}

func Home(w http.ResponseWriter, r *http.Request) {
	ProxyToBackend(w, r)
}

func Login(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	_ = r.FormValue("pass") // Using pass variable to avoid unused warning
	fmt.Fprintf(w, "Login sanitized: %s", user)
}

func Echo(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("msg")
	fmt.Fprintf(w, "Echo sanitized: %s", msg)
}

func Flood(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Flood endpoint.")
}

// API endpoints that proxy to backend
func APIHandler(w http.ResponseWriter, r *http.Request) {
	ProxyToBackend(w, r)
}

func AboutHandler(w http.ResponseWriter, r *http.Request) {
	ProxyToBackend(w, r)
}

func ContactHandler(w http.ResponseWriter, r *http.Request) {
	ProxyToBackend(w, r)
}
