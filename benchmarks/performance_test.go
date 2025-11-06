package benchmarks

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"rhinowaf/handlers"
	"rhinowaf/waf"
	"rhinowaf/waf/sanitize"
	"testing"
)

// Benchmark basic handler without any WAF protection
func BenchmarkHandlerNoWAF(b *testing.B) {
	req := httptest.NewRequest("GET", "/", nil)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handlers.Home(w, req)
	}
}

// Benchmark handler with full WAF protection
func BenchmarkHandlerWithWAF(b *testing.B) {
	handler := waf.AdaptiveProtect(handlers.Home)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler(w, req)
	}
}

// Benchmark sanitization on clean input
func BenchmarkSanitizeCleanInput(b *testing.B) {
	req := httptest.NewRequest("GET", "/?name=john&email=test@example.com", nil)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		sanitize.All(req)
	}
}

// Benchmark sanitization on malicious input
func BenchmarkSanitizeMaliciousInput(b *testing.B) {
	req := httptest.NewRequest("GET", "/?q=<script>alert('xss')</script>&sql=1'+OR+'1'='1", nil)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		sanitize.All(req)
	}
}

// Benchmark malicious pattern detection
func BenchmarkIsMaliciousCheck(b *testing.B) {
	tests := []struct {
		name string
		req  *http.Request
	}{
		{
			name: "Clean",
			req:  httptest.NewRequest("GET", "/?name=john", nil),
		},
		{
			name: "SQLInjection",
			req:  httptest.NewRequest("GET", "/?id=1'+OR+'1'='1", nil),
		},
		{
			name: "XSS",
			req:  httptest.NewRequest("GET", "/?msg=<script>alert(1)</script>", nil),
		},
		{
			name: "UnionSelect",
			req:  httptest.NewRequest("GET", "/?id=1+UNION+SELECT+*+FROM+users", nil),
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = sanitize.IsMalicious(tt.req)
			}
		})
	}
}

// Benchmark header validation
func BenchmarkHeaderValidation(b *testing.B) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Custom-Header", "value")
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = sanitize.ValidateHeaders(req)
	}
}

// Benchmark POST request with form data
func BenchmarkPOSTWithFormData(b *testing.B) {
	handler := waf.AdaptiveProtect(handlers.Login)
	formData := "user=testuser&pass=testpass123"
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/login", bytes.NewBufferString(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		handler(w, req)
	}
}

// Benchmark concurrent requests
func BenchmarkConcurrentRequests(b *testing.B) {
	handler := waf.AdaptiveProtect(handlers.Home)
	
	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		
		for pb.Next() {
			w := httptest.NewRecorder()
			handler(w, req)
		}
	})
}

// Benchmark large query parameters
func BenchmarkLargeQueryParams(b *testing.B) {
	handler := waf.AdaptiveProtect(handlers.APIHandler)
	longString := bytes.Repeat([]byte("a"), 1000)
	url := "/api/?data=" + string(longString)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", url, nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		handler(w, req)
	}
}

// Benchmark request with multiple headers
func BenchmarkMultipleHeaders(b *testing.B) {
	handler := waf.AdaptiveProtect(handlers.Home)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Cache-Control", "max-age=0")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.Header.Set("Referer", "https://example.com")
		w := httptest.NewRecorder()
		handler(w, req)
	}
}

// Benchmark body reading and sanitization
func BenchmarkBodySanitization(b *testing.B) {
	jsonBody := `{"username":"test","email":"test@example.com","message":"Hello World"}`
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/api/", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		sanitize.All(req)
	}
}

// Benchmark throughput - measure requests per second
func BenchmarkThroughput(b *testing.B) {
	handler := waf.AdaptiveProtect(handlers.Home)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.168.1.1:1234"
			w := httptest.NewRecorder()
			handler(w, req)
			io.ReadAll(w.Result().Body)
			w.Result().Body.Close()
		}
	})
}
