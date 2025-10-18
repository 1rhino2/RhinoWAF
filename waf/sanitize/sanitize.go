package sanitize

import (
	"html"
	"net/http"
	"regexp"
	"strings"
)

// Pre-compiled regexes for performance
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

	// Detection patterns
	sqlOrEqualRegex = regexp.MustCompile(`(?i)or\s+\d+=\d+`)
	dropTableRegex  = regexp.MustCompile(`(?i)drop\s+table`)
)

// All sanitizes ALL input vectors in an HTTP request
func All(r *http.Request) {
	// 1. Sanitize URL query parameters
	q := r.URL.Query()
	for k, vals := range q {
		for i, v := range vals {
			q[k][i] = Clean(v)
		}
	}
	r.URL.RawQuery = q.Encode()

	// 2. Sanitize URL path (protects against path traversal in route params)
	r.URL.Path = Clean(r.URL.Path)

	// 3. Sanitize form data (POST, PUT, PATCH)
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		r.ParseForm()
		for k, vals := range r.Form {
			for i, v := range vals {
				r.Form[k][i] = Clean(v)
			}
		}
		// Also sanitize PostForm (non-URL-encoded POST data)
		for k, vals := range r.PostForm {
			for i, v := range vals {
				r.PostForm[k][i] = Clean(v)
			}
		}
	}

	// 4. Sanitize multipart form data (file uploads, etc.)
	if r.MultipartForm != nil {
		for k, vals := range r.MultipartForm.Value {
			for i, v := range vals {
				r.MultipartForm.Value[k][i] = Clean(v)
			}
		}
		// Note: File content sanitization is intentionally skipped
		// as it could corrupt binary data. Filename sanitization is included.
		for k, files := range r.MultipartForm.File {
			for i, fh := range files {
				r.MultipartForm.File[k][i].Filename = Clean(fh.Filename)
			}
		}
	}

	// 5. Sanitize HTTP headers (excluding critical ones)
	criticalHeaders := map[string]bool{
		"Content-Type":      true,
		"Content-Length":    true,
		"Host":              true,
		"Connection":        true,
		"Transfer-Encoding": true,
	}
	for k, vals := range r.Header {
		// Skip critical headers that could break HTTP
		if criticalHeaders[k] {
			continue
		}
		for i, v := range vals {
			r.Header[k][i] = Clean(v)
		}
	}

	// 6. Sanitize cookies
	for _, c := range r.Cookies() {
		c.Value = Clean(c.Value)
		// Also sanitize cookie name (prevents header injection)
		c.Name = Clean(c.Name)
	}

	// 7. Sanitize URL fragment (rarely used server-side but just in case)
	r.URL.Fragment = Clean(r.URL.Fragment)

	// 8. Sanitize basic auth credentials (if present)
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
	check := func(s string) bool {
		s = strings.ToLower(s)
		if strings.Contains(s, "<script") || strings.Contains(s, "javascript:") || strings.Contains(s, "union select") {
			return true
		}
		if sqlOrEqualRegex.MatchString(s) {
			return true
		}
		if dropTableRegex.MatchString(s) {
			return true
		}
		return false
	}

	// 1. Check URL query parameters
	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			if check(v) {
				return true
			}
		}
	}

	// 2. Check URL path (path traversal, etc.)
	if check(r.URL.Path) {
		return true
	}

	// 3. Check form data
	r.ParseForm()
	for _, vals := range r.Form {
		for _, v := range vals {
			if check(v) {
				return true
			}
		}
	}

	// 4. Check PostForm separately
	for _, vals := range r.PostForm {
		for _, v := range vals {
			if check(v) {
				return true
			}
		}
	}

	// 5. Check multipart form values and filenames
	if r.MultipartForm != nil {
		for _, vals := range r.MultipartForm.Value {
			for _, v := range vals {
				if check(v) {
					return true
				}
			}
		}
		for _, files := range r.MultipartForm.File {
			for _, fh := range files {
				if check(fh.Filename) {
					return true
				}
			}
		}
	}

	// 6. Check headers (excluding critical ones to avoid false positives)
	criticalHeaders := map[string]bool{
		"Content-Type":      true,
		"Content-Length":    true,
		"Host":              true,
		"User-Agent":        true, // Legitimate user agents might contain keywords
		"Accept":            true,
		"Accept-Encoding":   true,
		"Accept-Language":   true,
		"Connection":        true,
		"Transfer-Encoding": true,
	}
	for k, vals := range r.Header {
		if criticalHeaders[k] {
			continue
		}
		for _, v := range vals {
			if check(v) {
				return true
			}
		}
	}

	// 7. Check cookies
	for _, c := range r.Cookies() {
		if check(c.Value) || check(c.Name) {
			return true
		}
	}

	// 8. Check URL fragment
	if check(r.URL.Fragment) {
		return true
	}

	// 9. Check basic auth credentials
	if user, pass, ok := r.BasicAuth(); ok {
		if check(user) || check(pass) {
			return true
		}
	}

	return false
}
