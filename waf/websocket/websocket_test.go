package websocket

import (
	"net/http"
	"testing"
	"time"
)

func TestValidateUpgrade_NotWebSocket(t *testing.T) {
	config := Config{Enabled: true}
	handler := NewHandler(config)

	req, _ := http.NewRequest("GET", "/", nil)
	allowed, _ := handler.ValidateUpgrade(req, "192.168.1.1")

	if !allowed {
		t.Error("Expected non-WebSocket request to be allowed")
	}
}

func TestValidateUpgrade_ValidWebSocket(t *testing.T) {
	config := Config{
		Enabled:        true,
		AllowedOrigins: []string{"https://example.com"},
	}
	handler := NewHandler(config)

	req, _ := http.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Origin", "https://example.com")

	allowed, _ := handler.ValidateUpgrade(req, "192.168.1.1")

	if !allowed {
		t.Error("Expected valid WebSocket upgrade to be allowed")
	}
}

func TestValidateUpgrade_InvalidOrigin(t *testing.T) {
	config := Config{
		Enabled:        true,
		AllowedOrigins: []string{"https://example.com"},
	}
	handler := NewHandler(config)

	req, _ := http.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Origin", "https://malicious.com")

	allowed, reason := handler.ValidateUpgrade(req, "192.168.1.1")

	if allowed {
		t.Error("Expected invalid origin to be blocked")
	}
	if reason != "WebSocket origin not allowed" {
		t.Errorf("Expected origin error, got: %s", reason)
	}
}

func TestValidateUpgrade_WildcardOrigin(t *testing.T) {
	config := Config{
		Enabled:        true,
		AllowedOrigins: []string{"*.example.com"},
	}
	handler := NewHandler(config)

	req, _ := http.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Origin", "https://subdomain.example.com")

	allowed, _ := handler.ValidateUpgrade(req, "192.168.1.1")

	if !allowed {
		t.Error("Expected wildcard origin to match")
	}
}

func TestValidateUpgrade_ConnectionRateLimit(t *testing.T) {
	config := Config{
		Enabled:              true,
		ConnectionRateLimit:  2,
		ConnectionRateWindow: time.Second,
		AllowOriginWildcard:  true,
	}
	handler := NewHandler(config)

	req, _ := http.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Origin", "https://example.com")

	ip := "192.168.1.1"

	allowed1, _ := handler.ValidateUpgrade(req, ip)
	if !allowed1 {
		t.Error("First connection should be allowed")
	}

	allowed2, _ := handler.ValidateUpgrade(req, ip)
	if !allowed2 {
		t.Error("Second connection should be allowed")
	}

	allowed3, reason := handler.ValidateUpgrade(req, ip)
	if allowed3 {
		t.Error("Third connection should be rate limited")
	}
	if reason != "WebSocket connection rate limit exceeded" {
		t.Errorf("Expected rate limit error, got: %s", reason)
	}
}

func TestValidateUpgrade_MaxConnectionsPerIP(t *testing.T) {
	config := Config{
		Enabled:             true,
		MaxConnectionsPerIP: 2,
		AllowOriginWildcard: true,
	}
	handler := NewHandler(config)

	req, _ := http.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Origin", "https://example.com")

	ip := "192.168.1.1"

	handler.RegisterConnection(ip)
	handler.RegisterConnection(ip)

	allowed, reason := handler.ValidateUpgrade(req, ip)
	if allowed {
		t.Error("Expected connection limit to be enforced")
	}
	if reason != "Maximum WebSocket connections per IP exceeded" {
		t.Errorf("Expected max connections error, got: %s", reason)
	}
}

func TestValidateUpgrade_RequireSubprotocol(t *testing.T) {
	config := Config{
		Enabled:             true,
		RequireSubprotocol:  true,
		AllowedSubprotocols: []string{"chat", "notifications"},
		AllowOriginWildcard: true,
	}
	handler := NewHandler(config)

	req, _ := http.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Sec-WebSocket-Protocol", "chat")

	allowed, _ := handler.ValidateUpgrade(req, "192.168.1.1")
	if !allowed {
		t.Error("Expected valid subprotocol to be allowed")
	}
}

func TestValidateUpgrade_InvalidSubprotocol(t *testing.T) {
	config := Config{
		Enabled:             true,
		RequireSubprotocol:  true,
		AllowedSubprotocols: []string{"chat"},
		AllowOriginWildcard: true,
	}
	handler := NewHandler(config)

	req, _ := http.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Sec-WebSocket-Protocol", "invalid")

	allowed, reason := handler.ValidateUpgrade(req, "192.168.1.1")
	if allowed {
		t.Error("Expected invalid subprotocol to be blocked")
	}
	if reason != "WebSocket subprotocol required but not provided or invalid" {
		t.Errorf("Expected subprotocol error, got: %s", reason)
	}
}

func TestValidateMessage_SizeLimit(t *testing.T) {
	config := Config{
		Enabled:        true,
		MaxMessageSize: 1024,
	}
	handler := NewHandler(config)

	allowed1, _ := handler.ValidateMessage("192.168.1.1", 512, false)
	if !allowed1 {
		t.Error("Expected message under limit to be allowed")
	}

	allowed2, reason := handler.ValidateMessage("192.168.1.1", 2048, false)
	if allowed2 {
		t.Error("Expected message over limit to be blocked")
	}
	if reason != "WebSocket message size exceeds limit" {
		t.Errorf("Expected size error, got: %s", reason)
	}
}

func TestValidateMessage_BinaryBlocking(t *testing.T) {
	config := Config{
		Enabled:             true,
		BlockBinaryMessages: true,
	}
	handler := NewHandler(config)

	allowed1, _ := handler.ValidateMessage("192.168.1.1", 100, false)
	if !allowed1 {
		t.Error("Expected text message to be allowed")
	}

	allowed2, reason := handler.ValidateMessage("192.168.1.1", 100, true)
	if allowed2 {
		t.Error("Expected binary message to be blocked")
	}
	if reason != "Binary WebSocket messages not allowed" {
		t.Errorf("Expected binary error, got: %s", reason)
	}
}

func TestValidateMessage_MessageRateLimit(t *testing.T) {
	config := Config{
		Enabled:           true,
		MessageRateLimit:  2,
		MessageRateWindow: time.Second,
	}
	handler := NewHandler(config)

	ip := "192.168.1.1"

	allowed1, _ := handler.ValidateMessage(ip, 100, false)
	if !allowed1 {
		t.Error("First message should be allowed")
	}

	allowed2, _ := handler.ValidateMessage(ip, 100, false)
	if !allowed2 {
		t.Error("Second message should be allowed")
	}

	allowed3, reason := handler.ValidateMessage(ip, 100, false)
	if allowed3 {
		t.Error("Third message should be rate limited")
	}
	if reason != "WebSocket message rate limit exceeded" {
		t.Errorf("Expected rate limit error, got: %s", reason)
	}
}

func TestRegisterUnregisterConnection(t *testing.T) {
	config := Config{Enabled: true}
	handler := NewHandler(config)

	ip := "192.168.1.1"
	conn := handler.RegisterConnection(ip)

	if conn.IP != ip {
		t.Errorf("Expected IP %s, got %s", ip, conn.IP)
	}

	stats := handler.GetStats()
	if stats["total_connections"].(int) != 1 {
		t.Errorf("Expected 1 connection, got %d", stats["total_connections"])
	}

	handler.UnregisterConnection(ip, conn)

	stats = handler.GetStats()
	if stats["total_connections"].(int) != 0 {
		t.Errorf("Expected 0 connections after unregister, got %d", stats["total_connections"])
	}
}

func TestViolationBanning(t *testing.T) {
	config := Config{
		Enabled:              true,
		MaxViolations:        3,
		ViolationBanDuration: time.Second,
		AllowOriginWildcard:  true,
	}
	handler := NewHandler(config)

	ip := "192.168.1.1"
	handler.RegisterConnection(ip)

	handler.recordViolation(ip)
	handler.recordViolation(ip)
	handler.recordViolation(ip)

	req, _ := http.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Origin", "https://example.com")

	allowed, reason := handler.ValidateUpgrade(req, ip)
	if allowed {
		t.Error("Expected banned IP to be blocked")
	}
	if reason != "IP temporarily banned due to WebSocket violations" {
		t.Errorf("Expected ban error, got: %s", reason)
	}

	time.Sleep(time.Second + 100*time.Millisecond)

	allowed2, _ := handler.ValidateUpgrade(req, ip)
	if !allowed2 {
		t.Error("Expected ban to expire after duration")
	}
}

func TestCleanup(t *testing.T) {
	config := Config{
		Enabled:              true,
		ConnectionRateWindow: 100 * time.Millisecond,
		MessageRateWindow:    100 * time.Millisecond,
	}
	handler := NewHandler(config)

	ip := "192.168.1.1"
	handler.checkConnectionRate(ip)
	handler.checkMessageRate(ip)

	time.Sleep(300 * time.Millisecond)
	handler.cleanup()

	handler.mu.RLock()
	connRates := len(handler.connRates[ip])
	msgRates := len(handler.msgRates[ip])
	handler.mu.RUnlock()

	if connRates > 0 {
		t.Error("Expected old connection rates to be cleaned up")
	}
	if msgRates > 0 {
		t.Error("Expected old message rates to be cleaned up")
	}
}
