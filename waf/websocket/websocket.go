package websocket

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

type ConnectionInfo struct {
	IP             string
	EstablishedAt  time.Time
	MessageCount   int64
	BytesSent      int64
	BytesReceived  int64
	LastMessageAt  time.Time
	ViolationCount int
}

type Config struct {
	Enabled              bool
	MaxConnectionsPerIP  int
	ConnectionRateLimit  int
	ConnectionRateWindow time.Duration
	MaxMessageSize       int64
	MessageRateLimit     int
	MessageRateWindow    time.Duration
	AllowedOrigins       []string
	AllowOriginWildcard  bool
	BlockBinaryMessages  bool
	InspectTextMessages  bool
	MaxViolations        int
	ViolationBanDuration time.Duration
	IdleTimeout          time.Duration
	HandshakeTimeout     time.Duration
	EnableCompression    bool
	RequireSubprotocol   bool
	AllowedSubprotocols  []string
	BlockPingFlood       bool
	MaxPingsPerMinute    int
}

type Handler struct {
	config      Config
	connections map[string][]*ConnectionInfo
	connRates   map[string][]time.Time
	msgRates    map[string][]time.Time
	banned      map[string]time.Time
	mu          sync.RWMutex
}

func NewHandler(config Config) *Handler {
	if config.MaxConnectionsPerIP == 0 {
		config.MaxConnectionsPerIP = 10
	}
	if config.ConnectionRateLimit == 0 {
		config.ConnectionRateLimit = 5
	}
	if config.ConnectionRateWindow == 0 {
		config.ConnectionRateWindow = time.Minute
	}
	if config.MaxMessageSize == 0 {
		config.MaxMessageSize = 1024 * 1024 // 1MB
	}
	if config.MessageRateLimit == 0 {
		config.MessageRateLimit = 100
	}
	if config.MessageRateWindow == 0 {
		config.MessageRateWindow = time.Minute
	}
	if config.MaxViolations == 0 {
		config.MaxViolations = 5
	}
	if config.ViolationBanDuration == 0 {
		config.ViolationBanDuration = 30 * time.Minute
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 5 * time.Minute
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = 10 * time.Second
	}
	if config.MaxPingsPerMinute == 0 {
		config.MaxPingsPerMinute = 60
	}

	h := &Handler{
		config:      config,
		connections: make(map[string][]*ConnectionInfo),
		connRates:   make(map[string][]time.Time),
		msgRates:    make(map[string][]time.Time),
		banned:      make(map[string]time.Time),
	}

	go h.cleanupLoop()
	return h
}

func (h *Handler) ValidateUpgrade(r *http.Request, ip string) (bool, string) {
	if !h.config.Enabled {
		return true, ""
	}

	h.mu.RLock()
	if banExpiry, exists := h.banned[ip]; exists {
		if time.Now().Before(banExpiry) {
			h.mu.RUnlock()
			return false, "IP temporarily banned due to WebSocket violations"
		}
	}
	h.mu.RUnlock()

	if !h.isWebSocketUpgrade(r) {
		return true, ""
	}

	if !h.validateOrigin(r) {
		h.recordViolation(ip)
		return false, "WebSocket origin not allowed"
	}

	if h.config.RequireSubprotocol {
		if !h.validateSubprotocol(r) {
			h.recordViolation(ip)
			return false, "WebSocket subprotocol required but not provided or invalid"
		}
	}

	if !h.checkConnectionRate(ip) {
		h.recordViolation(ip)
		return false, "WebSocket connection rate limit exceeded"
	}

	h.mu.RLock()
	activeConns := len(h.connections[ip])
	h.mu.RUnlock()

	if activeConns >= h.config.MaxConnectionsPerIP {
		h.recordViolation(ip)
		return false, "Maximum WebSocket connections per IP exceeded"
	}

	return true, ""
}

func (h *Handler) isWebSocketUpgrade(r *http.Request) bool {
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	connection := strings.ToLower(r.Header.Get("Connection"))
	return upgrade == "websocket" && strings.Contains(connection, "upgrade")
}

func (h *Handler) validateOrigin(r *http.Request) bool {
	if len(h.config.AllowedOrigins) == 0 && !h.config.AllowOriginWildcard {
		return true
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Sec-WebSocket-Origin")
	}

	if origin == "" {
		return false
	}

	if h.config.AllowOriginWildcard {
		return true
	}

	for _, allowed := range h.config.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
		if strings.HasPrefix(allowed, "*.") {
			domain := strings.TrimPrefix(allowed, "*.")
			if strings.HasSuffix(origin, domain) {
				return true
			}
		}
	}

	return false
}

func (h *Handler) validateSubprotocol(r *http.Request) bool {
	if len(h.config.AllowedSubprotocols) == 0 {
		return true
	}

	requested := r.Header.Get("Sec-WebSocket-Protocol")
	if requested == "" {
		return false
	}

	protocols := strings.Split(requested, ",")
	for _, proto := range protocols {
		proto = strings.TrimSpace(proto)
		for _, allowed := range h.config.AllowedSubprotocols {
			if proto == allowed {
				return true
			}
		}
	}

	return false
}

func (h *Handler) checkConnectionRate(ip string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-h.config.ConnectionRateWindow)

	timestamps := h.connRates[ip]
	filtered := make([]time.Time, 0)
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			filtered = append(filtered, ts)
		}
	}

	if len(filtered) >= h.config.ConnectionRateLimit {
		return false
	}

	filtered = append(filtered, now)
	h.connRates[ip] = filtered
	return true
}

func (h *Handler) RegisterConnection(ip string) *ConnectionInfo {
	h.mu.Lock()
	defer h.mu.Unlock()

	conn := &ConnectionInfo{
		IP:            ip,
		EstablishedAt: time.Now(),
		LastMessageAt: time.Now(),
	}

	h.connections[ip] = append(h.connections[ip], conn)
	return conn
}

func (h *Handler) UnregisterConnection(ip string, conn *ConnectionInfo) {
	h.mu.Lock()
	defer h.mu.Unlock()

	conns := h.connections[ip]
	filtered := make([]*ConnectionInfo, 0)
	for _, c := range conns {
		if c != conn {
			filtered = append(filtered, c)
		}
	}

	if len(filtered) > 0 {
		h.connections[ip] = filtered
	} else {
		delete(h.connections, ip)
	}
}

func (h *Handler) ValidateMessage(ip string, messageSize int64, isBinary bool) (bool, string) {
	if !h.config.Enabled {
		return true, ""
	}

	if messageSize > h.config.MaxMessageSize {
		h.recordViolation(ip)
		return false, "WebSocket message size exceeds limit"
	}

	if isBinary && h.config.BlockBinaryMessages {
		h.recordViolation(ip)
		return false, "Binary WebSocket messages not allowed"
	}

	if !h.checkMessageRate(ip) {
		h.recordViolation(ip)
		return false, "WebSocket message rate limit exceeded"
	}

	return true, ""
}

func (h *Handler) checkMessageRate(ip string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-h.config.MessageRateWindow)

	timestamps := h.msgRates[ip]
	filtered := make([]time.Time, 0)
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			filtered = append(filtered, ts)
		}
	}

	if len(filtered) >= h.config.MessageRateLimit {
		return false
	}

	filtered = append(filtered, now)
	h.msgRates[ip] = filtered
	return true
}

func (h *Handler) recordViolation(ip string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, conn := range h.connections[ip] {
		conn.ViolationCount++
		if conn.ViolationCount >= h.config.MaxViolations {
			h.banned[ip] = time.Now().Add(h.config.ViolationBanDuration)
			break
		}
	}
}

func (h *Handler) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		h.cleanup()
	}
}

func (h *Handler) cleanup() {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()

	for ip, conns := range h.connections {
		filtered := make([]*ConnectionInfo, 0)
		for _, conn := range conns {
			if now.Sub(conn.LastMessageAt) < h.config.IdleTimeout {
				filtered = append(filtered, conn)
			}
		}
		if len(filtered) > 0 {
			h.connections[ip] = filtered
		} else {
			delete(h.connections, ip)
		}
	}

	connCutoff := now.Add(-h.config.ConnectionRateWindow * 2)
	for ip, timestamps := range h.connRates {
		filtered := make([]time.Time, 0)
		for _, ts := range timestamps {
			if ts.After(connCutoff) {
				filtered = append(filtered, ts)
			}
		}
		if len(filtered) > 0 {
			h.connRates[ip] = filtered
		} else {
			delete(h.connRates, ip)
		}
	}

	msgCutoff := now.Add(-h.config.MessageRateWindow * 2)
	for ip, timestamps := range h.msgRates {
		filtered := make([]time.Time, 0)
		for _, ts := range timestamps {
			if ts.After(msgCutoff) {
				filtered = append(filtered, ts)
			}
		}
		if len(filtered) > 0 {
			h.msgRates[ip] = filtered
		} else {
			delete(h.msgRates, ip)
		}
	}

	for ip, expiry := range h.banned {
		if now.After(expiry) {
			delete(h.banned, ip)
		}
	}
}

func (h *Handler) GetStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	totalConns := 0
	for _, conns := range h.connections {
		totalConns += len(conns)
	}

	return map[string]interface{}{
		"total_connections": totalConns,
		"unique_ips":        len(h.connections),
		"banned_ips":        len(h.banned),
	}
}
