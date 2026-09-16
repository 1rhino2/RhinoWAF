package engine

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
)

func benchEngine(b *testing.B) *Engine {
	b.Helper()
	rs, err := Loader{}.Load()
	if err != nil {
		b.Fatal(err)
	}
	return New(DefaultConfig(), rs)
}

// a typical browser GET: 5 query params, 12 headers, 2 cookies
func BenchmarkInspectGET(b *testing.B) {
	e := benchEngine(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("GET", "/products?category=shoes&color=red&size=10&page=2&sort=price_asc", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128")
		r.Header.Set("Accept", "text/html,application/xhtml+xml")
		r.Header.Set("Accept-Language", "en-US,en;q=0.9")
		r.Header.Set("Accept-Encoding", "gzip, deflate, br")
		r.Header.Set("Referer", "https://example.com/")
		r.Header.Set("Cookie", "session=abc123def456; theme=dark")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Ch-Ua-Platform", "Windows")
		r.Header.Set("Connection", "keep-alive")
		r.Header.Set("Cache-Control", "max-age=0")
		if e.Inspect(r).Blocked() {
			b.Fatal("benign GET blocked")
		}
	}
}

// a form login POST with a real attack in it
func BenchmarkInspectFormAttack(b *testing.B) {
	e := benchEngine(b)
	body := "user=admin%27+or+1%3D1--&pass=x&remember=1"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("POST", "/login", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("User-Agent", "Mozilla/5.0")
		if !e.Inspect(r).Blocked() {
			b.Fatal("attack not blocked")
		}
	}
}

func bigJSON(n int) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"items":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(`{"id":`)
		buf.WriteString(itoa(i))
		buf.WriteString(`,"name":"product number `)
		buf.WriteString(itoa(i))
		buf.WriteString(`","description":"a perfectly ordinary description with some words in it","tags":["red","large","sale"],"price":19.99}`)
	}
	buf.WriteString(`]}`)
	return buf.Bytes()
}

// ~100 KB clean json api body, every string leaf gets inspected
func BenchmarkInspectJSON100KB(b *testing.B) {
	e := benchEngine(b)
	body := bigJSON(700)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("POST", "/api/bulk", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("User-Agent", "python-requests/2.32")
		if e.Inspect(r).Blocked() {
			b.Fatal("benign json blocked")
		}
	}
}

// 500 form fields, the max_args ceiling
func BenchmarkInspectForm500Args(b *testing.B) {
	e := benchEngine(b)
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString("field")
		sb.WriteString(itoa(i))
		sb.WriteString("=some+ordinary+value+")
		sb.WriteString(itoa(i))
	}
	body := sb.String()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("POST", "/submit", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if e.Inspect(r).Blocked() {
			b.Fatal("benign form blocked")
		}
	}
}
