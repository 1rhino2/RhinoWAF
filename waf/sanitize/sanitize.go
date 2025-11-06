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
	// check raw query string first to catch attacks before URL parsing
	if isMaliciousString(r.URL.RawQuery) {
		return true
	}
	
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
		"Accept": true, "Accept-Encoding": true,
		"Accept-Language": true, "Connection": true,
	}
	
	for k, vals := range r.Header {
		for _, v := range vals {
			// check for CRLF injection
			if strings.Contains(v, "\r") || strings.Contains(v, "\n") {
				return true
			}
			
			// check for null bytes
			if strings.Contains(v, "\x00") {
				return true
			}
			
			// check for header smuggling patterns
			if strings.Contains(strings.ToLower(v), "transfer-encoding") ||
				strings.Contains(strings.ToLower(v), "content-length") {
				return true
			}
			
			if !criticalHeaders[k] {
				if isMaliciousString(v) {
					return true
				}
			}
		}
	}
	
	// check for authorization bypass headers
	bypassHeaders := []string{
		"X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
	}
	for _, h := range bypassHeaders {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	
	// check for localhost/internal IP in X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if strings.Contains(xff, "127.0.0.1") || strings.Contains(xff, "localhost") {
			return true
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
	return hasXSSPatterns(s) || hasSQLInjectionPatterns(s) || 
		hasPathTraversal(s) || hasCommandInjection(s) ||
		hasLDAPInjection(s) || hasNoSQLInjection(s) ||
		hasSSRFPatterns(s) || hasTemplateInjection(s)
}

func hasPathTraversal(s string) bool {
	if strings.Contains(s, "../") || strings.Contains(s, "..\\") {
		return true
	}
	if strings.Contains(s, "%2e%2e%2f") || strings.Contains(s, "%2e%2e/") ||
		strings.Contains(s, "..%2f") || strings.Contains(s, "%2e%2e%5c") {
		return true
	}
	if strings.Contains(s, "/etc/passwd") || strings.Contains(s, "/etc/shadow") ||
		strings.Contains(s, "windows\\system32") {
		return true
	}
	return false
}

func hasCommandInjection(s string) bool {
	// shell metacharacters
	if strings.Contains(s, "; cat ") || strings.Contains(s, "| whoami") ||
		strings.Contains(s, "; ls") || strings.Contains(s, "| ls") ||
		strings.Contains(s, "; id") || strings.Contains(s, "| id") {
		return true
	}
	
	// command substitution
	if strings.Contains(s, "`cat ") || strings.Contains(s, "$(wget") ||
		strings.Contains(s, "$(curl") || strings.Contains(s, "`id`") ||
		strings.Contains(s, "$(id)") {
		return true
	}
	
	// shellshock
	if strings.Contains(s, "() { :; };") {
		return true
	}
	
	return false
}

func hasLDAPInjection(s string) bool {
	if strings.Contains(s, "*)(uid=*") || strings.Contains(s, "*)(cn=*") ||
		strings.Contains(s, "admin)(&") || strings.Contains(s, "*)(|(*") {
		return true
	}
	return false
}

func hasNoSQLInjection(s string) bool {
	// MongoDB operators in JSON
	if strings.Contains(s, "\"$gt\"") || strings.Contains(s, "\"$ne\"") ||
		strings.Contains(s, "\"$where\"") || strings.Contains(s, "{\"$") {
		return true
	}
	// URL-encoded versions
	if strings.Contains(s, "%22$gt%22") || strings.Contains(s, "%22$ne%22") {
		return true
	}
	return false
}

func hasSSRFPatterns(s string) bool {
	// localhost/internal IPs
	if strings.Contains(s, "://localhost") || strings.Contains(s, "://127.0.0.1") ||
		strings.Contains(s, "://0.0.0.0") || strings.Contains(s, "http://10.") ||
		strings.Contains(s, "http://192.168.") || strings.Contains(s, "http://172.16.") {
		return true
	}
	// cloud metadata endpoints
	if strings.Contains(s, "169.254.169.254") || strings.Contains(s, "metadata.google") ||
		strings.Contains(s, "metadata.azure") {
		return true
	}
	return false
}

func hasTemplateInjection(s string) bool {
	// SSTI patterns
	if strings.Contains(s, "{{config") || strings.Contains(s, "{{request") ||
		strings.Contains(s, "{{7*7}}") || strings.Contains(s, "${7*7}") {
		return true
	}
	// Ruby/ERB
	if strings.Contains(s, "<%= system(") || strings.Contains(s, "<% system(") {
		return true
	}
	return false
}

func hasXSSPatterns(s string) bool {
	// basic script tags
	if strings.Contains(s, "<script") || strings.Contains(s, "</script") {
		return true
	}
	
	// protocol handlers
	if strings.Contains(s, "javascript:") || strings.Contains(s, "vbscript:") ||
		strings.Contains(s, "data:") || strings.Contains(s, "file:") {
		return true
	}
	
	// event handlers (comprehensive list)
	eventHandlers := []string{
		"onerror=", "onload=", "onmouseover=", "onclick=", "onfocus=",
		"onblur=", "onchange=", "onsubmit=", "onkeydown=", "onkeyup=",
		"onmouseout=", "onmousemove=", "ondblclick=", "oncontextmenu=",
		"oninput=", "onselect=", "onwheel=", "ondrag=", "ondrop=",
		"onanimationend=", "onanimationstart=", "ontransitionend=",
		"onloadstart=", "onpointerover=", "ontoggle=",
	}
	for _, handler := range eventHandlers {
		if strings.Contains(s, handler) {
			return true
		}
	}
	
	// HTML tags that can execute scripts
	if strings.Contains(s, "<iframe") || strings.Contains(s, "<svg") ||
		strings.Contains(s, "<embed") || strings.Contains(s, "<object") ||
		strings.Contains(s, "<form") || strings.Contains(s, "<link") ||
		strings.Contains(s, "<meta") || strings.Contains(s, "<base") ||
		strings.Contains(s, "<img") || strings.Contains(s, "<video") ||
		strings.Contains(s, "<audio") || strings.Contains(s, "<body") ||
		strings.Contains(s, "<input") || strings.Contains(s, "<details") ||
		strings.Contains(s, "<template") || strings.Contains(s, "<slot") {
		return true
	}
	
	// CSS injection
	if strings.Contains(s, "expression(") || strings.Contains(s, "@import") ||
		strings.Contains(s, "behavior:") || strings.Contains(s, "url(") {
		return true
	}
	
	// DOM-based and special patterns
	if strings.Contains(s, "document.") || strings.Contains(s, "window.") ||
		strings.Contains(s, "eval(") || strings.Contains(s, "alert(") ||
		strings.Contains(s, "prompt(") || strings.Contains(s, "confirm(") {
		return true
	}
	
	// XML/XHTML vectors
	if strings.Contains(s, "<![cdata[") || strings.Contains(s, "<!entity") ||
		strings.Contains(s, "xmlns") {
		return true
	}
	
	// Template injection
	if strings.Contains(s, "{{constructor") || strings.Contains(s, "dangerouslysetinnerhtml") ||
		strings.Contains(s, "v-html") || strings.Contains(s, "${") {
		return true
	}
	
	// Encoding bypasses
	if strings.Contains(s, "&#") || strings.Contains(s, "\\u") ||
		strings.Contains(s, "\\x") || strings.Contains(s, "%3c") ||
		strings.Contains(s, "%3e") {
		return true
	}
	
	return false
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

	// stacked queries - improved detection
	if strings.Contains(s, "; delete") || strings.Contains(s, "; drop") ||
		strings.Contains(s, "; update") || strings.Contains(s, "; insert") ||
		strings.Contains(s, ";delete") || strings.Contains(s, ";drop") ||
		strings.Contains(s, ";update") || strings.Contains(s, ";insert") {
		return true
	}

	// batch queries with multiple statements
	if strings.Count(s, ";") >= 2 {
		return true
	}

	// comment variations - improved
	if (strings.Contains(s, "/*") && strings.Contains(s, "*/")) ||
		strings.Contains(s, "/**/") {
		return true
	}
	if strings.Contains(s, "--") || strings.HasSuffix(s, "#") {
		if containsSQLKeyword(s) || strings.Contains(s, "or") || strings.Contains(s, "and") {
			return true
		}
	}

	// encoding bypasses
	if strings.Contains(s, "\\u") || strings.Contains(s, "0x") ||
		strings.Contains(s, "char(") || strings.Contains(s, "chr(") {
		return true
	}

	// time-based blind
	if strings.Contains(s, "sleep(") || strings.Contains(s, "benchmark(") ||
		strings.Contains(s, "pg_sleep") || strings.Contains(s, "waitfor") {
		return true
	}

	// advanced functions - improved
	if strings.Contains(s, "exec(") || strings.Contains(s, "execute(") ||
		strings.Contains(s, "exec ") || strings.Contains(s, "execute ") ||
		strings.Contains(s, "xp_cmdshell") || strings.Contains(s, "sp_executesql") ||
		strings.Contains(s, "into outfile") || strings.Contains(s, "into dumpfile") ||
		strings.Contains(s, "load_file") || strings.Contains(s, "load data") {
		return true
	}

	// privilege escalation - improved
	if strings.Contains(s, "grant all") || strings.Contains(s, "grant ") ||
		strings.Contains(s, "create user") || strings.Contains(s, "alter user") ||
		strings.Contains(s, "revoke ") || strings.Contains(s, "identified by") {
		return true
	}

	// nosql injection - check for MongoDB operators
	if strings.Contains(s, "[$ne]") || strings.Contains(s, "[$gt]") ||
		strings.Contains(s, "[$lt]") || strings.Contains(s, "[$regex]") ||
		strings.Contains(s, "[$where]") || strings.Contains(s, "[$in]") {
		return true
	}

	// boolean blind variations
	if strings.Contains(s, "or true") || strings.Contains(s, "and false") ||
		strings.Contains(s, "ascii(") || strings.Contains(s, "substring(") ||
		strings.Contains(s, "length(") {
		return true
	}

	// error-based
	if strings.Contains(s, "updatexml") || strings.Contains(s, "extractvalue") ||
		strings.Contains(s, "convert(") {
		return true
	}

	// order/group by - only flag if combined with dangerous patterns
	if (strings.Contains(s, "order by") || strings.Contains(s, "group by")) {
		if strings.Contains(s, "union") || strings.Contains(s, "select") ||
			strings.Contains(s, "--") || strings.Contains(s, "#") {
			return true
		}
	}

	// database fingerprinting
	if strings.Contains(s, "version()") || strings.Contains(s, "@@version") ||
		strings.Contains(s, "database()") || strings.Contains(s, "user()") {
		return true
	}

	// out-of-band exfil
	if strings.Contains(s, "load_file") || strings.Contains(s, "utl_http") ||
		strings.Contains(s, "dbms_pipe") || strings.Contains(s, "master..") ||
		strings.Contains(s, "openrowset") {
		return true
	}

	// batch queries - semicolon with SQL keywords
	if strings.Contains(s, ";") {
		if containsSQLKeyword(s) || strings.Contains(s, "select") ||
			strings.Contains(s, "delete") || strings.Contains(s, "update") ||
			strings.Contains(s, "insert") || strings.Contains(s, "drop") {
			return true
		}
	}

	// double encoding
	if strings.Contains(s, "%2527") || strings.Contains(s, "%252f") ||
		strings.Contains(s, "%2522") {
		return true
	}

	// standalone dangerous patterns
	if s == "1'--" || s == "1'#" || s == "1';" || strings.HasSuffix(s, "'--") {
		return true
	}

	return sqlOrEqualRegex.MatchString(s) || dropTableRegex.MatchString(s)
}

func containsSQLKeyword(s string) bool {
	keywords := []string{"select", "union", "insert", "update", "delete", "drop", "create", "alter", "exec", "execute", "grant"}
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
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
