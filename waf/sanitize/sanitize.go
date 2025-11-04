package sanitize

import (
	"html"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

// pre-compiled for performance
var (
	sqlCommentRegex   = regexp.MustCompile(`--|\b(AND|OR)\b.*?\b(=|>|<)\b`)
	semicolonRegex    = regexp.MustCompile(`;`)
	sqlKeywordsRegex  = regexp.MustCompile(`(?i)\b(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|CREATE|ALTER|TRUNCATE|EXEC)\b`)
	javascriptRegex   = regexp.MustCompile(`(?i)javascript:`)
	eventHandlerRegex = regexp.MustCompile(`(?i)on\w+\s*=`)
	base64Regex       = regexp.MustCompile(`(?i)base64,?[a-zA-Z0-9+/=]*`)
	hexRegex          = regexp.MustCompile(`0x[0-9a-fA-F]+`)
	htmlTagRegex      = regexp.MustCompile(`(?i)<.*?>`)
	schemeRegex       = regexp.MustCompile(`(?i)(data|vbscript|file):`)

	sqlOrEqualRegex = regexp.MustCompile(`(?i)or\s+\d+=\d+`)
	dropTableRegex  = regexp.MustCompile(`(?i)drop\s+table`)

	// header injection detection
	crlfRegex        = regexp.MustCompile(`[\r\n]`)
	headerSplitRegex = regexp.MustCompile(`[\r\n]\s*[a-zA-Z-]+\s*:`)
)

// All sanitizes ALL input vectors in an HTTP request
func All(r *http.Request) {
	q := r.URL.Query()
	for k, vals := range q {
		for i, v := range vals {
			q[k][i] = Clean(v)
		}
	}
	r.URL.RawQuery = q.Encode()

	r.URL.Path = Clean(r.URL.Path)

	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		_ = r.ParseForm()
		for k, vals := range r.Form {
			for i, v := range vals {
				r.Form[k][i] = Clean(v)
			}
		}
		for k, vals := range r.PostForm {
			for i, v := range vals {
				r.PostForm[k][i] = Clean(v)
			}
		}
	}

	if r.MultipartForm != nil {
		for k, vals := range r.MultipartForm.Value {
			for i, v := range vals {
				r.MultipartForm.Value[k][i] = Clean(v)
			}
		}
		for k, files := range r.MultipartForm.File {
			for i, fh := range files {
				r.MultipartForm.File[k][i].Filename = Clean(fh.Filename)
			}
		}
	}

	criticalHeaders := map[string]bool{
		"Content-Type":      true,
		"Content-Length":    true,
		"Host":              true,
		"Connection":        true,
		"Transfer-Encoding": true,
	}
	for k, vals := range r.Header {
		if criticalHeaders[k] {
			continue
		}
		for i, v := range vals {
			r.Header[k][i] = Clean(v)
		}
	}

	for _, c := range r.Cookies() {
		c.Value = Clean(c.Value)
		c.Name = Clean(c.Name)
	}

	r.URL.Fragment = Clean(r.URL.Fragment)

	if user, pass, ok := r.BasicAuth(); ok {
		r.SetBasicAuth(Clean(user), Clean(pass))
	}
}

func Clean(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		return r
	}, s)
	s = html.EscapeString(s)
	s = strings.ReplaceAll(s, "'", "&#39;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	s = strings.ReplaceAll(s, "\\", "")
	s = sqlCommentRegex.ReplaceAllString(s, "")
	s = semicolonRegex.ReplaceAllString(s, "")
	s = sqlKeywordsRegex.ReplaceAllString(s, "")
	s = javascriptRegex.ReplaceAllString(s, "")
	s = eventHandlerRegex.ReplaceAllString(s, "")
	s = base64Regex.ReplaceAllString(s, "")
	s = hexRegex.ReplaceAllString(s, "")
	s = htmlTagRegex.ReplaceAllString(s, "")
	s = schemeRegex.ReplaceAllString(s, "")
	return s
}

// IsMalicious checks ALL input vectors for malicious patterns
func IsMalicious(r *http.Request) bool {
	return checkQueryParams(r) || checkPath(r) || checkFormData(r) ||
		checkMultipartForm(r) || checkHeaders(r) || checkCookies(r) ||
		checkFragment(r) || checkBasicAuth(r)
}

func checkQueryParams(r *http.Request) bool {
	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			if isMaliciousString(v) {
				return true
			}
		}
	}
	return false
}

func checkPath(r *http.Request) bool {
	return isMaliciousString(r.URL.Path)
}

func checkFormData(r *http.Request) bool {
	_ = r.ParseForm()
	for _, vals := range r.Form {
		for _, v := range vals {
			if isMaliciousString(v) {
				return true
			}
		}
	}
	for _, vals := range r.PostForm {
		for _, v := range vals {
			if isMaliciousString(v) {
				return true
			}
		}
	}
	return false
}

func checkMultipartForm(r *http.Request) bool {
	if r.MultipartForm == nil {
		return false
	}
	for _, vals := range r.MultipartForm.Value {
		for _, v := range vals {
			if isMaliciousString(v) {
				return true
			}
		}
	}
	for _, files := range r.MultipartForm.File {
		for _, fh := range files {
			if isMaliciousString(fh.Filename) {
				return true
			}
		}
	}
	return false
}

func checkHeaders(r *http.Request) bool {
	criticalHeaders := map[string]bool{
		"Content-Type": true, "Content-Length": true, "Host": true,
		"User-Agent": true, "Accept": true, "Accept-Encoding": true,
		"Accept-Language": true, "Connection": true, "Transfer-Encoding": true,
	}
	for k, vals := range r.Header {
		if criticalHeaders[k] {
			continue
		}
		for _, v := range vals {
			if isMaliciousString(v) {
				return true
			}
		}
	}
	return false
}

func checkCookies(r *http.Request) bool {
	for _, c := range r.Cookies() {
		if isMaliciousString(c.Value) || isMaliciousString(c.Name) {
			return true
		}
	}
	return false
}

func checkFragment(r *http.Request) bool {
	return isMaliciousString(r.URL.Fragment)
}

func checkBasicAuth(r *http.Request) bool {
	if user, pass, ok := r.BasicAuth(); ok {
		return isMaliciousString(user) || isMaliciousString(pass)
	}
	return false
}

func isMaliciousString(s string) bool {
	s = strings.ToLower(s)
	return hasXSSPatterns(s) || hasSQLInjectionPatterns(s)
}

func hasXSSPatterns(s string) bool {
	return strings.Contains(s, "<script") || strings.Contains(s, "javascript:") ||
		strings.Contains(s, "onerror=") || strings.Contains(s, "onload=") ||
		strings.Contains(s, "<iframe") || strings.Contains(s, "<svg")
}

func hasSQLInjectionPatterns(s string) bool {
	if strings.Contains(s, "union select") || strings.Contains(s, "union all select") {
		return true
	}
	if strings.Contains(s, "drop table") || strings.Contains(s, "drop database") {
		return true
	}
	if strings.Contains(s, "' or '1'='1") || strings.Contains(s, "' or 1=1") ||
		strings.Contains(s, "\" or \"1\"=\"1") || strings.Contains(s, "or 1=1--") {
		return true
	}
	if strings.Contains(s, "'; exec") || strings.Contains(s, "'; drop") {
		return true
	}
	if strings.Contains(s, "waitfor delay") {
		return true
	}
	if strings.Contains(s, "' order by") && strings.Contains(s, "--") {
		return true
	}
	if strings.Contains(s, "admin'--") || strings.Contains(s, "admin' --") {
		return true
	}
	if (strings.Contains(s, "' and ") || strings.Contains(s, "' or ")) &&
		(strings.Contains(s, "'='") || strings.Contains(s, "=")) {
		return true
	}
	return sqlOrEqualRegex.MatchString(s) || dropTableRegex.MatchString(s)
}

// ValidateHeaders checks for malformed or malicious headers
// Returns true if headers are valid, false otherwise
func ValidateHeaders(r *http.Request) (bool, string) {
	// Check for excessively long header values (potential buffer overflow)
	const maxHeaderLength = 8192

	for name, values := range r.Header {
		// Validate header name
		if !isValidHeaderName(name) {
			return false, "invalid header name: " + name
		}

		for _, value := range values {
			// Check for null bytes
			if strings.Contains(value, "\x00") {
				return false, "null byte in header value: " + name
			}

			// Check for CRLF injection (header splitting)
			if crlfRegex.MatchString(value) {
				return false, "CRLF characters in header value: " + name
			}

			// Check for header injection attempts
			if headerSplitRegex.MatchString(value) {
				return false, "header injection attempt detected: " + name
			}

			// Check length
			if len(value) > maxHeaderLength {
				return false, "header value too long: " + name
			}

			// Check for invalid UTF-8
			if !utf8.ValidString(value) {
				return false, "invalid UTF-8 in header: " + name
			}
		}
	}

	// Validate Host header
	host := r.Host
	if host == "" {
		return false, "missing Host header"
	}

	// Check for suspicious characters in Host header
	if strings.ContainsAny(host, "\r\n\x00") {
		return false, "invalid characters in Host header"
	}

	// Validate Content-Length if present
	if contentLength := r.Header.Get("Content-Length"); contentLength != "" {
		// Content-Length should only contain digits
		if !regexp.MustCompile(`^\d+$`).MatchString(contentLength) {
			return false, "invalid Content-Length header"
		}
	}

	// Check for duplicate critical headers
	criticalHeaders := []string{"Host", "Content-Length", "Transfer-Encoding"}
	for _, header := range criticalHeaders {
		if len(r.Header[header]) > 1 {
			return false, "duplicate " + header + " header"
		}
	}

	// Detect smuggling attempts (conflicting Content-Length and Transfer-Encoding)
	if r.Header.Get("Content-Length") != "" && r.Header.Get("Transfer-Encoding") != "" {
		return false, "both Content-Length and Transfer-Encoding present (smuggling attempt)"
	}

	return true, ""
}

// isValidHeaderName checks if a header name contains only valid characters
func isValidHeaderName(name string) bool {
	if name == "" {
		return false
	}

	// Header names should only contain alphanumeric characters and hyphens
	// and should not start or end with a hyphen
	validNameRegex := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$|^[a-zA-Z]$`)
	return validNameRegex.MatchString(name)
}
